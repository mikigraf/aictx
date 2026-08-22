use crate::automation::contracts::{
    AutomationErrorCode, AutomationOperation, LeaseReasonCode, LeaseStatus,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseDomainError {
    InvalidTransition {
        from: LeaseStatus,
        to: LeaseStatus,
    },
    TerminalImmutable(LeaseStatus),
    LeaseNotActive,
    LeaseExpired,
    LeaseRevoked,
    CallerUnauthorized,
    GenerationMismatch,
    GenerationExhausted,
    SessionLimitReached,
    TenantMismatch,
    RunMismatch,
    RoleMismatch,
    HostMismatch,
    PolicyBindingMismatch,
    InvalidReason {
        status: LeaseStatus,
        reason: LeaseReasonCode,
    },
    ClockBeforeIssuance,
    ClockGenerationMismatch,
    MonotonicRegression,
    ClockOverflow,
    InvalidSnapshot,
}

impl LeaseDomainError {
    #[must_use]
    pub const fn automation_code(&self, operation: AutomationOperation) -> AutomationErrorCode {
        match self {
            Self::InvalidReason { .. } => AutomationErrorCode::InvalidRequest,
            Self::CallerUnauthorized => AutomationErrorCode::CallerUnauthorized,
            Self::LeaseExpired => state_code(operation, AutomationErrorCode::LeaseExpired),
            Self::LeaseRevoked => state_code(operation, AutomationErrorCode::LeaseRevoked),
            Self::GenerationMismatch => {
                control_code(operation, AutomationErrorCode::GenerationMismatch, true)
            }
            Self::SessionLimitReached => {
                control_code(operation, AutomationErrorCode::SessionLimitReached, false)
            }
            Self::TenantMismatch => {
                control_code(operation, AutomationErrorCode::TenantMismatch, true)
            }
            Self::RunMismatch => control_code(operation, AutomationErrorCode::RunMismatch, true),
            Self::RoleMismatch => control_code(operation, AutomationErrorCode::RoleMismatch, true),
            Self::HostMismatch => control_code(operation, AutomationErrorCode::HostMismatch, true),
            Self::InvalidTransition { .. } | Self::TerminalImmutable(_) | Self::LeaseNotActive => {
                lease_not_active_code(operation)
            }
            Self::GenerationExhausted
            | Self::PolicyBindingMismatch
            | Self::ClockBeforeIssuance
            | Self::ClockGenerationMismatch
            | Self::MonotonicRegression
            | Self::ClockOverflow
            | Self::InvalidSnapshot => AutomationErrorCode::InternalError,
        }
    }
}

const fn state_code(
    operation: AutomationOperation,
    code: AutomationErrorCode,
) -> AutomationErrorCode {
    match operation {
        AutomationOperation::LeaseRenew
        | AutomationOperation::LeaseClose
        | AutomationOperation::ExecutionStart => code,
        AutomationOperation::LeaseRevoke => AutomationErrorCode::LeaseNotActive,
        _ => AutomationErrorCode::InternalError,
    }
}

const fn control_code(
    operation: AutomationOperation,
    code: AutomationErrorCode,
    close_allows: bool,
) -> AutomationErrorCode {
    match operation {
        AutomationOperation::LeaseRenew | AutomationOperation::ExecutionStart => code,
        AutomationOperation::LeaseClose if close_allows => code,
        _ => AutomationErrorCode::InternalError,
    }
}

const fn lease_not_active_code(operation: AutomationOperation) -> AutomationErrorCode {
    match operation {
        AutomationOperation::LeaseRenew
        | AutomationOperation::LeaseRevoke
        | AutomationOperation::LeaseClose
        | AutomationOperation::ExecutionStart => AutomationErrorCode::LeaseNotActive,
        _ => AutomationErrorCode::InternalError,
    }
}
