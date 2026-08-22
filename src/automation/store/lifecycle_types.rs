use core::fmt;

use crate::automation::{
    contracts::{
        AutomationError, AutomationErrorSchema, AutomationOperation, CallerSubject,
        ClientRequestId, HostIdentity, IdentityLeaseResponse, LeaseId, LeaseStatus, ProfileUid,
        RefusalCode,
    },
    lease::LeaseDomainError,
};

use super::StoreError;

/// Mechanical non-capacity refusal code for the unwired store seam. This does
/// not prove policy freshness or authorization; activation owns capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NonCapacityRefusal(RefusalCode);

impl NonCapacityRefusal {
    #[must_use]
    pub(super) const fn from_evaluation(code: RefusalCode) -> Option<Self> {
        if matches!(code, RefusalCode::CapacityExceeded) {
            None
        } else {
            Some(Self(code))
        }
    }

    pub(super) const fn code(self) -> RefusalCode {
        self.0
    }
}

/// Authenticated identity and optimistic version for a requested lease.
///
/// Construction remains inside the sealed store/service boundary. The caller
/// and host values must come from authenticated transport evidence, never from
/// an untrusted request body.
pub(crate) struct AuthenticatedRequestControl<'a> {
    lease_id: &'a LeaseId,
    expected_row_version: u64,
    caller_subject: &'a CallerSubject,
    host_identity: &'a HostIdentity,
}

impl<'a> AuthenticatedRequestControl<'a> {
    #[must_use]
    pub(crate) const fn new(
        lease_id: &'a LeaseId,
        expected_row_version: u64,
        caller_subject: &'a CallerSubject,
        host_identity: &'a HostIdentity,
    ) -> Self {
        Self {
            lease_id,
            expected_row_version,
            caller_subject,
            host_identity,
        }
    }

    pub(super) const fn lease_id(&self) -> &LeaseId {
        self.lease_id
    }

    pub(super) const fn expected_row_version(&self) -> u64 {
        self.expected_row_version
    }

    pub(super) const fn caller_subject(&self) -> &CallerSubject {
        self.caller_subject
    }

    pub(super) const fn host_identity(&self) -> &HostIdentity {
        self.host_identity
    }
}

/// A domain result whose resulting aggregate was committed atomically.
///
/// Storage/integrity failures are returned by the outer store `Result`. A
/// domain error stays here because the pure transition may have advanced the
/// monotonic high-water or moved the lease to a fail-closed state first.
pub(crate) struct CommittedMutation<T> {
    operation: AutomationOperation,
    response: Option<IdentityLeaseResponse>,
    row_version: Option<u64>,
    domain_result: Result<T, LeaseDomainError>,
    cleanup_deferred: bool,
}

impl<T> CommittedMutation<T> {
    pub(super) const fn new(
        operation: AutomationOperation,
        response: IdentityLeaseResponse,
        row_version: u64,
        domain_result: Result<T, LeaseDomainError>,
    ) -> Self {
        Self {
            operation,
            response: Some(response),
            row_version: Some(row_version),
            domain_result,
            cleanup_deferred: false,
        }
    }

    pub(super) fn authentication_denied(operation: AutomationOperation) -> Self {
        Self {
            operation,
            response: None,
            row_version: None,
            domain_result: Err(LeaseDomainError::CallerUnauthorized),
            cleanup_deferred: false,
        }
    }

    #[must_use]
    pub(crate) fn successful_response(&self) -> Option<&IdentityLeaseResponse> {
        self.domain_result
            .is_ok()
            .then_some(self.response.as_ref())
            .flatten()
    }

    #[must_use]
    pub(crate) fn successful_row_version(&self) -> Option<u64> {
        self.domain_result
            .is_ok()
            .then_some(self.row_version)
            .flatten()
    }

    pub(crate) const fn domain_result(&self) -> &Result<T, LeaseDomainError> {
        &self.domain_result
    }

    pub(crate) fn into_domain_result(self) -> Result<T, LeaseDomainError> {
        self.domain_result
    }

    #[must_use]
    pub(crate) const fn cleanup_deferred(&self) -> bool {
        self.domain_result.is_ok() && self.cleanup_deferred
    }

    pub(super) fn mark_cleanup_deferred(&mut self) {
        self.cleanup_deferred = true;
    }

    /// Build the operation-specific wire error without exposing the committed
    /// response carried internally for post-mutation validation.
    pub(crate) fn automation_error(
        &self,
        client_request_id: Option<ClientRequestId>,
        syntactic_lease_id: &LeaseId,
    ) -> Result<Option<AutomationError>, StoreError> {
        let Some(domain) = self.domain_result.as_ref().err() else {
            return Ok(None);
        };
        let code = domain.automation_code(self.operation);
        let mut error = AutomationError {
            schema: AutomationErrorSchema,
            operation: self.operation,
            code,
            client_request_id,
            lease_id: Some(syntactic_lease_id.clone()),
        };
        if error.validate().is_err() {
            error.lease_id = None;
        }
        error
            .validate()
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
        Ok(Some(error))
    }
}

impl<T> fmt::Debug for CommittedMutation<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("CommittedMutation");
        debug.field("domain_succeeded", &self.domain_result.is_ok());
        if self.domain_result.is_ok()
            && let (Some(response), Some(row_version)) = (&self.response, self.row_version)
        {
            debug
                .field("cleanup_deferred", &self.cleanup_deferred)
                .field("lease_id", &response.lease_id)
                .field("status", &response.status)
                .field("row_version", &row_version);
        }
        debug.finish_non_exhaustive()
    }
}

/// Non-secret accounting returned by one transactional retention pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PruneResult {
    requests: u64,
    leases: u64,
    reservations: u64,
    processes: u64,
    events: u64,
}

impl PruneResult {
    pub(super) const fn new(
        requests: u64,
        leases: u64,
        reservations: u64,
        processes: u64,
        events: u64,
    ) -> Self {
        Self {
            requests,
            leases,
            reservations,
            processes,
            events,
        }
    }

    #[must_use]
    pub(crate) const fn deleted_requests(self) -> u64 {
        self.requests
    }

    #[must_use]
    pub(crate) const fn deleted_leases(self) -> u64 {
        self.leases
    }

    #[must_use]
    pub(crate) const fn deleted_reservations(self) -> u64 {
        self.reservations
    }

    #[must_use]
    pub(crate) const fn deleted_processes(self) -> u64 {
        self.processes
    }

    #[must_use]
    pub(crate) const fn deleted_events(self) -> u64 {
        self.events
    }

    #[must_use]
    pub(crate) const fn changed(self) -> bool {
        self.requests != 0
            || self.leases != 0
            || self.reservations != 0
            || self.processes != 0
            || self.events != 0
    }
}

/// Result of a post-terminal capacity release attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapacityReleaseResult {
    released: u64,
    row_version: u64,
    profile_uid: ProfileUid,
    cleanup_deferred: bool,
}

impl CapacityReleaseResult {
    pub(super) const fn new(released: u64, row_version: u64, profile_uid: ProfileUid) -> Self {
        Self {
            released,
            row_version,
            profile_uid,
            cleanup_deferred: false,
        }
    }

    #[must_use]
    pub(crate) const fn released(&self) -> u64 {
        self.released
    }

    #[must_use]
    pub(crate) const fn row_version(&self) -> u64 {
        self.row_version
    }

    #[must_use]
    pub(crate) const fn profile_uid(&self) -> &ProfileUid {
        &self.profile_uid
    }

    #[must_use]
    pub(crate) const fn cleanup_deferred(&self) -> bool {
        self.cleanup_deferred
    }

    pub(super) fn mark_cleanup_deferred(&mut self) {
        self.cleanup_deferred = true;
    }
}

pub(super) const fn terminal_status(status: LeaseStatus) -> bool {
    matches!(
        status,
        LeaseStatus::Closed | LeaseStatus::Revoked | LeaseStatus::Expired | LeaseStatus::Refused
    )
}
