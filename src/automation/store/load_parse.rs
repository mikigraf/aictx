use rusqlite::Row;

use crate::automation::{
    contracts::{
        AgentRole, AutomationAuthMode, FencingGeneration, IsolationClassification, LeaseReasonCode,
        LeaseStatus, UtcTimestamp,
    },
    lease::ServiceClockGeneration,
};

use super::{StoreError, records::StoredTimestamp, security::MAX_SERVICE_GENERATION};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryState {
    None,
    Required,
    Reconciling,
}

#[derive(Clone)]
pub(super) struct RawTimestamp {
    wire: String,
    seconds: i64,
    nanos: i64,
}

impl RawTimestamp {
    pub(super) fn validate(self) -> Result<UtcTimestamp, StoreError> {
        let value = UtcTimestamp::parse(self.wire).map_err(|_| StoreError::IntegrityCheckFailed)?;
        let checked =
            StoredTimestamp::from_utc(&value).map_err(|_| StoreError::IntegrityCheckFailed)?;
        if checked.seconds == self.seconds && checked.nanos == self.nanos {
            Ok(value)
        } else {
            Err(StoreError::IntegrityCheckFailed)
        }
    }
}

#[derive(Clone)]
pub(super) struct OptionalRawTimestamp {
    wire: Option<String>,
    seconds: Option<i64>,
    nanos: Option<i64>,
}

impl OptionalRawTimestamp {
    pub(super) fn validate(self) -> Result<Option<UtcTimestamp>, StoreError> {
        match (self.wire, self.seconds, self.nanos) {
            (None, None, None) => Ok(None),
            (Some(wire), Some(seconds), Some(nanos)) => RawTimestamp {
                wire,
                seconds,
                nanos,
            }
            .validate()
            .map(Some),
            _ => Err(StoreError::IntegrityCheckFailed),
        }
    }

    pub(super) fn any_present(&self) -> bool {
        self.wire.is_some() || self.seconds.is_some() || self.nanos.is_some()
    }
}

pub(super) fn required_timestamp(row: &Row<'_>, start: usize) -> rusqlite::Result<RawTimestamp> {
    Ok(RawTimestamp {
        wire: row.get(start)?,
        seconds: row.get(start + 1)?,
        nanos: row.get(start + 2)?,
    })
}

pub(super) fn optional_timestamp(
    row: &Row<'_>,
    start: usize,
) -> rusqlite::Result<OptionalRawTimestamp> {
    Ok(OptionalRawTimestamp {
        wire: row.get(start)?,
        seconds: row.get(start + 1)?,
        nanos: row.get(start + 2)?,
    })
}

pub(super) fn parse_u128(value: &[u8]) -> Result<u128, StoreError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    Ok(u128::from_be_bytes(bytes))
}

pub(super) fn parse_optional_u128(value: Option<&[u8]>) -> Result<Option<u128>, StoreError> {
    value.map(parse_u128).transpose()
}

pub(super) fn parse_generation(value: i64) -> Result<ServiceClockGeneration, StoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_SERVICE_GENERATION).contains(value))
        .map(ServiceClockGeneration::from_value)
        .ok_or(StoreError::IntegrityCheckFailed)
}

pub(super) fn parse_fencing(value: Option<i64>) -> Result<FencingGeneration, StoreError> {
    value
        .and_then(|value| u64::try_from(value).ok())
        .and_then(|value| FencingGeneration::from_value(value).ok())
        .ok_or(StoreError::IntegrityCheckFailed)
}

pub(super) fn parse_required<T>(value: Option<&str>) -> Result<T, StoreError>
where
    T: std::str::FromStr,
{
    value
        .ok_or(StoreError::IntegrityCheckFailed)?
        .parse()
        .map_err(|_| StoreError::IntegrityCheckFailed)
}

pub(super) fn parse_optional<T>(value: Option<&str>) -> Result<Option<T>, StoreError>
where
    T: std::str::FromStr,
{
    value
        .map(str::parse)
        .transpose()
        .map_err(|_| StoreError::IntegrityCheckFailed)
}

pub(super) fn parse_status(value: &str) -> Result<LeaseStatus, StoreError> {
    Ok(match value {
        "REQUESTED" => LeaseStatus::Requested,
        "ACTIVE" => LeaseStatus::Active,
        "RENEWING" => LeaseStatus::Renewing,
        "CLOSED" => LeaseStatus::Closed,
        "REVOKED" => LeaseStatus::Revoked,
        "EXPIRED" => LeaseStatus::Expired,
        "REFUSED" => LeaseStatus::Refused,
        "ERROR" => LeaseStatus::Error,
        _ => return Err(StoreError::IntegrityCheckFailed),
    })
}

pub(super) fn parse_recovery_state(value: &str) -> Result<RecoveryState, StoreError> {
    Ok(match value {
        "NONE" => RecoveryState::None,
        "REQUIRED" => RecoveryState::Required,
        "RECONCILING" => RecoveryState::Reconciling,
        _ => return Err(StoreError::IntegrityCheckFailed),
    })
}

pub(super) fn parse_reason(value: &str) -> Result<LeaseReasonCode, StoreError> {
    Ok(match value {
        "completed" => LeaseReasonCode::Completed,
        "worker-failed" => LeaseReasonCode::WorkerFailed,
        "operator-revoked" => LeaseReasonCode::OperatorRevoked,
        "policy-revoked" => LeaseReasonCode::PolicyRevoked,
        "principal-mismatch" => LeaseReasonCode::PrincipalMismatch,
        "lease-expired" => LeaseReasonCode::LeaseExpired,
        "maximum-lifetime-reached" => LeaseReasonCode::MaximumLifetimeReached,
        "heartbeat-lost" => LeaseReasonCode::HeartbeatLost,
        "process-unverifiable" => LeaseReasonCode::ProcessUnverifiable,
        "generation-superseded" => LeaseReasonCode::GenerationSuperseded,
        "renewal-acknowledgement-failed" => LeaseReasonCode::RenewalAcknowledgementFailed,
        "service-recovery" => LeaseReasonCode::ServiceRecovery,
        "internal-error" => LeaseReasonCode::InternalError,
        _ => return Err(StoreError::IntegrityCheckFailed),
    })
}

pub(super) fn parse_auth_mode(value: &str) -> Result<AutomationAuthMode, StoreError> {
    Ok(match value {
        "wif" => AutomationAuthMode::Wif,
        "subscription-token" => AutomationAuthMode::SubscriptionToken,
        "api-key" => AutomationAuthMode::ApiKey,
        "chatgpt-oauth" => AutomationAuthMode::ChatgptOauth,
        "access-token" => AutomationAuthMode::AccessToken,
        _ => return Err(StoreError::IntegrityCheckFailed),
    })
}

pub(super) fn parse_isolation(value: &str) -> Result<IsolationClassification, StoreError> {
    Ok(match value {
        "credential-isolated" => IsolationClassification::CredentialIsolated,
        "per-lease-isolated" => IsolationClassification::PerLeaseIsolated,
        "copied-credential-development" => IsolationClassification::CopiedCredentialDevelopment,
        _ => return Err(StoreError::IntegrityCheckFailed),
    })
}

pub(super) const fn role_label(value: AgentRole) -> &'static str {
    match value {
        AgentRole::Implementer => "implementer",
        AgentRole::LocalReviewer => "local-reviewer",
        AgentRole::PrReviewer => "pr-reviewer",
    }
}
