use std::fmt;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::automation::{
    contracts::{IdentityLeaseResponse, LeaseId, RefusalCode, UtcTimestamp},
    lease::{ClockSample, MonotonicMoment, ServiceClockGeneration},
};

use super::StoreError;

/// The durable result of the first request carrying a global client request ID.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum PersistedAcquireOutcome {
    Requested {
        response: IdentityLeaseResponse,
        issuance: PersistedIssuance,
    },
    Refused {
        response: IdentityLeaseResponse,
        issuance: PersistedIssuance,
        refusal_code: RefusalCode,
    },
    Resolved {
        response: IdentityLeaseResponse,
        issuance: PersistedIssuance,
    },
}

impl fmt::Debug for PersistedAcquireOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, response, issuance) = match self {
            Self::Requested { response, issuance } => ("requested", response, issuance),
            Self::Refused {
                response, issuance, ..
            } => ("refused", response, issuance),
            Self::Resolved { response, issuance } => ("resolved", response, issuance),
        };
        formatter
            .debug_struct("PersistedAcquireOutcome")
            .field("kind", &kind)
            .field("lease_id", &response.lease_id)
            .field("status", &response.status)
            .field("issuance", issuance)
            .finish_non_exhaustive()
    }
}

impl PersistedAcquireOutcome {
    #[must_use]
    pub const fn lease_id(&self) -> &LeaseId {
        match self {
            Self::Requested { response, .. }
            | Self::Refused { response, .. }
            | Self::Resolved { response, .. } => &response.lease_id,
        }
    }

    #[must_use]
    pub(crate) const fn issuance(&self) -> &PersistedIssuance {
        match self {
            Self::Requested { issuance, .. }
            | Self::Refused { issuance, .. }
            | Self::Resolved { issuance, .. } => issuance,
        }
    }

    #[must_use]
    pub(crate) const fn response(&self) -> &IdentityLeaseResponse {
        match self {
            Self::Requested { response, .. }
            | Self::Refused { response, .. }
            | Self::Resolved { response, .. } => response,
        }
    }
}

/// Original wall/monotonic issuance anchor returned unchanged on replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersistedIssuance {
    issued_at: UtcTimestamp,
    monotonic: MonotonicMoment,
    service_generation: ServiceClockGeneration,
}

impl PersistedIssuance {
    pub(super) const fn new(
        issued_at: UtcTimestamp,
        monotonic: MonotonicMoment,
        service_generation: ServiceClockGeneration,
    ) -> Self {
        Self {
            issued_at,
            monotonic,
            service_generation,
        }
    }

    #[must_use]
    pub(crate) const fn issued_at(&self) -> &UtcTimestamp {
        &self.issued_at
    }

    #[must_use]
    pub(crate) const fn monotonic(&self) -> MonotonicMoment {
        self.monotonic
    }

    #[must_use]
    pub(crate) const fn service_generation(&self) -> ServiceClockGeneration {
        self.service_generation
    }

    #[must_use]
    pub(crate) fn clock_sample(&self) -> ClockSample {
        ClockSample::new(
            self.issued_at.clone(),
            self.monotonic,
            self.service_generation,
        )
    }
}

/// Result of atomically beginning or replaying an acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BeginAcquireResult {
    outcome: PersistedAcquireOutcome,
    replayed: bool,
    row_version: u64,
    cleanup_deferred: bool,
}

impl BeginAcquireResult {
    pub(super) const fn new(
        outcome: PersistedAcquireOutcome,
        replayed: bool,
        row_version: u64,
    ) -> Self {
        Self {
            outcome,
            replayed,
            row_version,
            cleanup_deferred: false,
        }
    }

    #[must_use]
    pub(crate) const fn outcome(&self) -> &PersistedAcquireOutcome {
        &self.outcome
    }

    #[must_use]
    pub(crate) const fn replayed(&self) -> bool {
        self.replayed
    }

    #[must_use]
    pub(crate) const fn row_version(&self) -> u64 {
        self.row_version
    }

    #[must_use]
    pub(crate) const fn cleanup_deferred(&self) -> bool {
        self.cleanup_deferred
    }

    pub(super) fn mark_cleanup_deferred(&mut self) {
        self.cleanup_deferred = true;
    }
}

pub(super) struct StoredTimestamp<'a> {
    pub(super) wire: &'a str,
    pub(super) seconds: i64,
    pub(super) nanos: i64,
}

impl<'a> StoredTimestamp<'a> {
    pub(super) fn from_utc(value: &'a UtcTimestamp) -> Result<Self, StoreError> {
        let instant = OffsetDateTime::parse(value.as_str(), &Rfc3339)
            .map_err(|_| StoreError::InvalidRequest)?;
        Ok(Self {
            wire: value.as_str(),
            seconds: instant.unix_timestamp(),
            nanos: i64::from(instant.nanosecond()),
        })
    }
}

pub(super) const fn role_label(role: crate::automation::contracts::AgentRole) -> &'static str {
    use crate::automation::contracts::AgentRole;
    match role {
        AgentRole::Implementer => "implementer",
        AgentRole::LocalReviewer => "local-reviewer",
        AgentRole::PrReviewer => "pr-reviewer",
    }
}

pub(super) const fn refusal_label(code: RefusalCode) -> &'static str {
    match code {
        RefusalCode::WorkOrderProofInvalid => "work-order-proof-invalid",
        RefusalCode::WorkOrderAuthorizationMismatch => "work-order-authorization-mismatch",
        RefusalCode::RequestedTtlNotAllowed => "requested-ttl-not-allowed",
        RefusalCode::PolicyDigestMismatch => "policy-digest-mismatch",
        RefusalCode::ProfileNotFound => "profile-not-found",
        RefusalCode::ProviderMismatch => "provider-mismatch",
        RefusalCode::ProfileNotEligible => "profile-not-eligible",
        RefusalCode::AuthenticationExceptionRequired => "authentication-exception-required",
        RefusalCode::IsolationExceptionRequired => "isolation-exception-required",
        RefusalCode::EnvironmentNotAllowed => "environment-not-allowed",
        RefusalCode::RoleNotAllowed => "role-not-allowed",
        RefusalCode::CallerNotAllowed => "caller-not-allowed",
        RefusalCode::RepositoryNotAllowed => "repository-not-allowed",
        RefusalCode::ProfileNotReady => "profile-not-ready",
        RefusalCode::IdentityTokenStale => "identity-token-stale",
        RefusalCode::HarnessUntrusted => "harness-untrusted",
        RefusalCode::PrincipalUnverified => "principal-unverified",
        RefusalCode::PrincipalMismatch => "principal-mismatch",
        RefusalCode::OrganizationMismatch => "organization-mismatch",
        RefusalCode::WorkspaceMismatch => "workspace-mismatch",
        RefusalCode::IsolationUnproven => "isolation-unproven",
        RefusalCode::CapacityExceeded => "capacity-exceeded",
    }
}

pub(super) fn parse_refusal(value: &str) -> Option<RefusalCode> {
    Some(match value {
        "work-order-proof-invalid" => RefusalCode::WorkOrderProofInvalid,
        "work-order-authorization-mismatch" => RefusalCode::WorkOrderAuthorizationMismatch,
        "requested-ttl-not-allowed" => RefusalCode::RequestedTtlNotAllowed,
        "policy-digest-mismatch" => RefusalCode::PolicyDigestMismatch,
        "profile-not-found" => RefusalCode::ProfileNotFound,
        "provider-mismatch" => RefusalCode::ProviderMismatch,
        "profile-not-eligible" => RefusalCode::ProfileNotEligible,
        "authentication-exception-required" => RefusalCode::AuthenticationExceptionRequired,
        "isolation-exception-required" => RefusalCode::IsolationExceptionRequired,
        "environment-not-allowed" => RefusalCode::EnvironmentNotAllowed,
        "role-not-allowed" => RefusalCode::RoleNotAllowed,
        "caller-not-allowed" => RefusalCode::CallerNotAllowed,
        "repository-not-allowed" => RefusalCode::RepositoryNotAllowed,
        "profile-not-ready" => RefusalCode::ProfileNotReady,
        "identity-token-stale" => RefusalCode::IdentityTokenStale,
        "harness-untrusted" => RefusalCode::HarnessUntrusted,
        "principal-unverified" => RefusalCode::PrincipalUnverified,
        "principal-mismatch" => RefusalCode::PrincipalMismatch,
        "organization-mismatch" => RefusalCode::OrganizationMismatch,
        "workspace-mismatch" => RefusalCode::WorkspaceMismatch,
        "isolation-unproven" => RefusalCode::IsolationUnproven,
        "capacity-exceeded" => RefusalCode::CapacityExceeded,
        _ => return None,
    })
}

pub(super) fn replay_retain_until(
    issued_at: &UtcTimestamp,
    authorization_expires_at: &UtcTimestamp,
) -> Result<UtcTimestamp, StoreError> {
    let issued = OffsetDateTime::parse(issued_at.as_str(), &Rfc3339)
        .map_err(|_| StoreError::InvalidRequest)?;
    let local_horizon = issued
        .checked_add(time::Duration::days(7))
        .ok_or(StoreError::InvalidRequest)?;
    let authorization_expiry = OffsetDateTime::parse(authorization_expires_at.as_str(), &Rfc3339)
        .map_err(|_| StoreError::InvalidRequest)?;
    let horizon = local_horizon.max(authorization_expiry);
    UtcTimestamp::parse(canonical_utc(horizon)).map_err(|_| StoreError::InvalidRequest)
}

pub(super) fn audit_retention_cutoff(now: &UtcTimestamp) -> Result<UtcTimestamp, StoreError> {
    let instant =
        OffsetDateTime::parse(now.as_str(), &Rfc3339).map_err(|_| StoreError::InvalidRequest)?;
    let cutoff = instant
        .checked_sub(time::Duration::days(7))
        .ok_or(StoreError::InvalidRequest)?;
    UtcTimestamp::parse(canonical_utc(cutoff)).map_err(|_| StoreError::InvalidRequest)
}

fn canonical_utc(value: OffsetDateTime) -> String {
    let mut output = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    );
    let nanos = value.nanosecond();
    if nanos != 0 {
        let fraction = format!("{nanos:09}");
        output.push('.');
        output.push_str(fraction.trim_end_matches('0'));
    }
    output.push('Z');
    output
}
