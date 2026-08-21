use serde::{Deserialize, Serialize};

use super::types::{ClientRequestId, ContractValidationError, LeaseId};

pub const AUTOMATION_ERROR_SCHEMA: &str = "ctxlane.automation-error/v1";

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct AutomationErrorSchema;

impl Serialize for AutomationErrorSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(AUTOMATION_ERROR_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for AutomationErrorSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if String::deserialize(deserializer)? == AUTOMATION_ERROR_SCHEMA {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "unsupported automation error schema; expected v1",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutomationOperation {
    ProfileList,
    ProfileReadiness,
    ProfileResolve,
    LeaseAcquire,
    LeaseInspect,
    LeaseRenew,
    LeaseRevoke,
    LeaseClose,
    ServiceHealth,
    ExecutionStart,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutomationErrorCode {
    InvalidRequest,
    UnsupportedSchema,
    CallerUnauthenticated,
    CallerUnauthorized,
    ProfileNotFound,
    ProviderMismatch,
    ProfileNotEligible,
    AuthenticationExceptionRequired,
    IsolationExceptionRequired,
    EnvironmentNotAllowed,
    RoleNotAllowed,
    CallerNotAllowed,
    RepositoryNotAllowed,
    ProfileNotReady,
    IdentityTokenStale,
    HarnessUntrusted,
    PrincipalUnverified,
    PrincipalMismatch,
    OrganizationMismatch,
    WorkspaceMismatch,
    IsolationUnproven,
    IdempotencyConflict,
    RateLimited,
    ServiceRecovering,
    UnsupportedPlatform,
    LeaseNotFound,
    LeaseNotActive,
    LeaseExpired,
    LeaseRevoked,
    GenerationMismatch,
    RunMismatch,
    RoleMismatch,
    TenantMismatch,
    HostMismatch,
    SessionLimitReached,
    StoreUnavailable,
    InternalError,
}

impl AutomationErrorCode {
    const fn is_common(self) -> bool {
        matches!(
            self,
            Self::InvalidRequest
                | Self::UnsupportedSchema
                | Self::CallerUnauthenticated
                | Self::CallerUnauthorized
                | Self::RateLimited
                | Self::ServiceRecovering
                | Self::UnsupportedPlatform
                | Self::StoreUnavailable
                | Self::InternalError
        )
    }

    const fn valid_for(self, operation: AutomationOperation) -> bool {
        if self.is_common() {
            return true;
        }
        match operation {
            AutomationOperation::ProfileList | AutomationOperation::ServiceHealth => false,
            AutomationOperation::ProfileReadiness => {
                matches!(self, Self::ProfileNotFound | Self::ProviderMismatch)
            }
            AutomationOperation::ProfileResolve => matches!(
                self,
                Self::ProfileNotFound
                    | Self::ProviderMismatch
                    | Self::ProfileNotEligible
                    | Self::AuthenticationExceptionRequired
                    | Self::IsolationExceptionRequired
                    | Self::EnvironmentNotAllowed
                    | Self::RoleNotAllowed
                    | Self::CallerNotAllowed
                    | Self::RepositoryNotAllowed
                    | Self::ProfileNotReady
                    | Self::IdentityTokenStale
                    | Self::HarnessUntrusted
                    | Self::PrincipalUnverified
                    | Self::PrincipalMismatch
                    | Self::OrganizationMismatch
                    | Self::WorkspaceMismatch
                    | Self::IsolationUnproven
            ),
            AutomationOperation::LeaseAcquire => matches!(self, Self::IdempotencyConflict),
            AutomationOperation::LeaseInspect => matches!(self, Self::LeaseNotFound),
            AutomationOperation::LeaseRenew => matches!(
                self,
                Self::LeaseNotFound
                    | Self::LeaseNotActive
                    | Self::LeaseExpired
                    | Self::LeaseRevoked
                    | Self::GenerationMismatch
                    | Self::RunMismatch
                    | Self::RoleMismatch
                    | Self::TenantMismatch
                    | Self::HostMismatch
                    | Self::SessionLimitReached
            ),
            AutomationOperation::LeaseRevoke => {
                matches!(self, Self::LeaseNotFound | Self::LeaseNotActive)
            }
            AutomationOperation::LeaseClose => matches!(
                self,
                Self::LeaseNotFound
                    | Self::LeaseNotActive
                    | Self::LeaseExpired
                    | Self::LeaseRevoked
                    | Self::GenerationMismatch
                    | Self::RunMismatch
                    | Self::RoleMismatch
                    | Self::TenantMismatch
                    | Self::HostMismatch
            ),
            AutomationOperation::ExecutionStart => matches!(
                self,
                Self::LeaseNotFound
                    | Self::LeaseNotActive
                    | Self::LeaseExpired
                    | Self::LeaseRevoked
                    | Self::GenerationMismatch
                    | Self::RunMismatch
                    | Self::RoleMismatch
                    | Self::TenantMismatch
                    | Self::HostMismatch
                    | Self::SessionLimitReached
                    | Self::ProfileNotReady
                    | Self::IdentityTokenStale
                    | Self::HarnessUntrusted
                    | Self::PrincipalUnverified
                    | Self::PrincipalMismatch
                    | Self::OrganizationMismatch
                    | Self::WorkspaceMismatch
                    | Self::IsolationUnproven
            ),
        }
    }

    const fn requires_lease_id(self, operation: AutomationOperation) -> bool {
        !self.is_common()
            && matches!(
                operation,
                AutomationOperation::LeaseInspect
                    | AutomationOperation::LeaseRenew
                    | AutomationOperation::LeaseRevoke
                    | AutomationOperation::LeaseClose
                    | AutomationOperation::ExecutionStart
            )
    }
}

#[derive(Deserialize)]
struct RequiredNullable<T>(Option<T>);

/// Stable code-only failure response. Human text belongs in a local catalog,
/// not on the public wire where backend data could be copied accidentally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationError {
    pub schema: AutomationErrorSchema,
    pub operation: AutomationOperation,
    pub code: AutomationErrorCode,
    pub client_request_id: Option<ClientRequestId>,
    pub lease_id: Option<LeaseId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AutomationErrorWire {
    schema: AutomationErrorSchema,
    operation: AutomationOperation,
    code: AutomationErrorCode,
    client_request_id: RequiredNullable<ClientRequestId>,
    lease_id: RequiredNullable<LeaseId>,
}

#[derive(Serialize)]
struct AutomationErrorWireRef<'a> {
    schema: AutomationErrorSchema,
    operation: AutomationOperation,
    code: AutomationErrorCode,
    client_request_id: &'a Option<ClientRequestId>,
    lease_id: &'a Option<LeaseId>,
}

impl AutomationError {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if !self.code.valid_for(self.operation) {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "automation error code is not valid for the operation",
            ));
        }
        if self.lease_id.is_some() != self.code.requires_lease_id(self.operation) {
            return Err(ContractValidationError::InvalidResponseInvariant(
                "automation error lease_id does not match the operation and code",
            ));
        }
        Ok(())
    }

    fn wire_ref(&self) -> AutomationErrorWireRef<'_> {
        AutomationErrorWireRef {
            schema: self.schema,
            operation: self.operation,
            code: self.code,
            client_request_id: &self.client_request_id,
            lease_id: &self.lease_id,
        }
    }
}

impl TryFrom<AutomationErrorWire> for AutomationError {
    type Error = ContractValidationError;

    fn try_from(value: AutomationErrorWire) -> Result<Self, Self::Error> {
        let error = Self {
            schema: value.schema,
            operation: value.operation,
            code: value.code,
            client_request_id: value.client_request_id.0,
            lease_id: value.lease_id.0,
        };
        error.validate()?;
        Ok(error)
    }
}

impl Serialize for AutomationError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        self.wire_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AutomationError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        AutomationErrorWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}
