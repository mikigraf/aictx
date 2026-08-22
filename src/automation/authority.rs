//! Sealed operator authority for a future local automation service.
//!
//! Loading this module is always explicit. Ordinary CLI and TUI paths never
//! read its configuration or construct any value in this module.

use std::{collections::BTreeSet, fmt, num::NonZeroU32, path::PathBuf};

use serde::Serialize;
use thiserror::Error;

use super::policy::{AllowScope, CapacityLimits, ControllerPolicy};
use crate::{
    automation::contracts::{
        AgentRole, CallerSubject, EnvironmentName, HostIdentity, KeyId, ProfileUid, Provider,
        RepositoryId, Sha256Digest, TenantId, WorkOrderAuthorization, WorkspaceId,
    },
    model::InstallationUid,
};

mod config;
mod signing;

const AUTHORITY_CONFIG_VERSION: u32 = 1;

/// Stable, value-free failures at the operator authority boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum AuthorityError {
    #[error("automation authority is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("automation authority configuration is unavailable")]
    Unavailable,
    #[error("automation authority configuration is too large")]
    TooLarge,
    #[error("automation authority configuration permissions or ownership are unsafe")]
    UnsafeConfiguration,
    #[error("automation authority configuration is invalid")]
    InvalidConfiguration,
    #[error("automation authority configuration belongs to another installation")]
    InstallationMismatch,
}

/// Deliberately indistinguishable key, signature, and authorization failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProofError {
    #[error("work-order proof is invalid")]
    WorkOrderProofInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AuthenticationAssurance {
    /// The connection-opening process passed the complete Linux attestation.
    ///
    /// This does not attest each writer on a stream after `fork` or descriptor
    /// passing. A future service must additionally match per-message
    /// `SCM_CREDENTIALS` to the retained live process identity before treating
    /// a message as authorized.
    LinuxConnectionAttested,
    MacosDevelopmentUnqualified,
}

impl AuthenticationAssurance {
    const fn permits_work_order_verification(self) -> bool {
        matches!(self, Self::MacosDevelopmentUnqualified)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceLimits {
    pub(crate) max_connections: u16,
    pub(crate) max_connections_per_controller: u16,
    pub(crate) max_frame_bytes: u32,
    pub(crate) read_timeout_milliseconds: u32,
    pub(crate) write_timeout_milliseconds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RateLimit {
    pub(crate) refill_per_minute: u32,
    pub(crate) burst: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerRateLimits {
    pub(crate) acquire: RateLimit,
    pub(crate) readiness: RateLimit,
    pub(crate) principal_mismatch: RateLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerCapacity {
    pub(crate) profile: u32,
    pub(crate) provider: u32,
    pub(crate) caller: u32,
    pub(crate) host: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct LinuxPeerPolicy {
    uid: u32,
    gid: u32,
    executable: PathBuf,
    executable_sha256: Sha256Digest,
    cgroup_v2_path: String,
    systemd_unit: String,
    executable_device: u64,
    executable_inode: u64,
}

impl LinuxPeerPolicy {
    #[cfg(test)]
    pub(crate) fn test_fixture(
        executable: PathBuf,
        executable_sha256: Sha256Digest,
        cgroup_v2_path: String,
        systemd_unit: String,
    ) -> Self {
        Self {
            uid: 1000,
            gid: 1000,
            executable,
            executable_sha256,
            cgroup_v2_path,
            systemd_unit,
            executable_device: 10,
            executable_inode: 20,
        }
    }

    pub(crate) const fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) const fn gid(&self) -> u32 {
        self.gid
    }

    pub(crate) fn executable(&self) -> &std::path::Path {
        &self.executable
    }

    pub(crate) const fn executable_sha256(&self) -> Sha256Digest {
        self.executable_sha256
    }

    pub(crate) fn cgroup_v2_path(&self) -> &str {
        &self.cgroup_v2_path
    }

    pub(crate) fn systemd_unit(&self) -> &str {
        &self.systemd_unit
    }

    pub(crate) const fn executable_device(&self) -> u64 {
        self.executable_device
    }

    pub(crate) const fn executable_inode(&self) -> u64 {
        self.executable_inode
    }
}

#[derive(Clone, Eq, PartialEq)]
enum ControllerAttestation {
    LinuxPeer(LinuxPeerPolicy),
    MacosDevelopmentUnqualified,
}

impl ControllerAttestation {
    const fn assurance(&self) -> AuthenticationAssurance {
        match self {
            Self::LinuxPeer(_) => AuthenticationAssurance::LinuxConnectionAttested,
            Self::MacosDevelopmentUnqualified => {
                AuthenticationAssurance::MacosDevelopmentUnqualified
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PreparedController {
    subject: CallerSubject,
    tenant_ids: BTreeSet<TenantId>,
    signing_key_ids: BTreeSet<KeyId>,
    profile_uids: BTreeSet<ProfileUid>,
    providers: BTreeSet<Provider>,
    environments: BTreeSet<EnvironmentName>,
    roles: Vec<AgentRole>,
    repositories: BTreeSet<RepositoryId>,
    workspace_ids: BTreeSet<WorkspaceId>,
    maximum_ttl_seconds: u64,
    maximum_session_seconds: u64,
    allow_authentication_exception: bool,
    allow_isolation_exception: bool,
    capacity: ControllerCapacity,
    rate_limits: ControllerRateLimits,
    attestation: ControllerAttestation,
}

impl PreparedController {
    #[must_use]
    pub(crate) const fn subject(&self) -> &CallerSubject {
        &self.subject
    }

    #[must_use]
    pub(crate) const fn assurance(&self) -> AuthenticationAssurance {
        self.attestation.assurance()
    }

    #[must_use]
    pub(crate) const fn rate_limits(&self) -> ControllerRateLimits {
        self.rate_limits
    }

    #[must_use]
    pub(crate) const fn linux_peer_policy(&self) -> Option<&LinuxPeerPolicy> {
        match &self.attestation {
            ControllerAttestation::LinuxPeer(policy) => Some(policy),
            ControllerAttestation::MacosDevelopmentUnqualified => None,
        }
    }

    #[must_use]
    pub(crate) const fn is_macos_development_unqualified(&self) -> bool {
        matches!(
            self.attestation,
            ControllerAttestation::MacosDevelopmentUnqualified
        )
    }

    /// Convert the prepared entry without introducing any `Any` scope.
    pub(crate) fn exact_policy(&self) -> Result<ControllerPolicy, AuthorityError> {
        let maximum_ttl_seconds =
            crate::automation::contracts::MaximumTtlSeconds::from_seconds(self.maximum_ttl_seconds)
                .map_err(|_| AuthorityError::InvalidConfiguration)?;
        let maximum_session_seconds = crate::automation::contracts::DurationSeconds::from_seconds(
            self.maximum_session_seconds,
        )
        .map_err(|_| AuthorityError::InvalidConfiguration)?;
        let capacity = CapacityLimits::new(
            NonZeroU32::new(self.capacity.profile).ok_or(AuthorityError::InvalidConfiguration)?,
            NonZeroU32::new(self.capacity.provider).ok_or(AuthorityError::InvalidConfiguration)?,
            NonZeroU32::new(self.capacity.caller).ok_or(AuthorityError::InvalidConfiguration)?,
            NonZeroU32::new(self.capacity.host).ok_or(AuthorityError::InvalidConfiguration)?,
        );
        Ok(ControllerPolicy {
            profile_uids: AllowScope::Only(self.profile_uids.iter().cloned().collect()),
            providers: AllowScope::Only(self.providers.iter().copied().collect()),
            environments: AllowScope::Only(self.environments.iter().cloned().collect()),
            roles: AllowScope::Only(self.roles.clone()),
            caller_subjects: AllowScope::Only(vec![self.subject.clone()]),
            repositories: AllowScope::Only(self.repositories.iter().cloned().collect()),
            maximum_ttl_seconds,
            maximum_session_seconds,
            capacity,
            allow_authentication_exception: self.allow_authentication_exception,
            allow_isolation_exception: self.allow_isolation_exception,
        })
    }
}

struct PreparedSigningKey {
    key_id: KeyId,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl fmt::Debug for PreparedSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSigningKey")
            .field("key_id", &self.key_id)
            .field("verifying_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

pub(crate) struct PreparedAuthority {
    installation_uid: InstallationUid,
    host_identity: HostIdentity,
    service_limits: ServiceLimits,
    failed_authentication_rate: RateLimit,
    signing_keys: Vec<PreparedSigningKey>,
    controllers: Vec<PreparedController>,
    configuration_digest: Sha256Digest,
}

impl PreparedAuthority {
    fn from_parts(
        installation_uid: InstallationUid,
        host_identity: HostIdentity,
        service_limits: ServiceLimits,
        failed_authentication_rate: RateLimit,
        signing_keys: Vec<PreparedSigningKey>,
        controllers: Vec<PreparedController>,
        configuration_digest: Sha256Digest,
    ) -> Self {
        Self {
            installation_uid,
            host_identity,
            service_limits,
            failed_authentication_rate,
            signing_keys,
            controllers,
            configuration_digest,
        }
    }

    #[must_use]
    pub(crate) const fn host_identity(&self) -> &HostIdentity {
        &self.host_identity
    }

    #[must_use]
    pub(crate) const fn service_limits(&self) -> ServiceLimits {
        self.service_limits
    }

    #[must_use]
    pub(crate) const fn failed_authentication_rate(&self) -> RateLimit {
        self.failed_authentication_rate
    }

    #[must_use]
    pub(crate) fn controllers(&self) -> &[PreparedController] {
        &self.controllers
    }

    #[must_use]
    pub(crate) const fn configuration_digest(&self) -> Sha256Digest {
        self.configuration_digest
    }

    #[must_use]
    pub(crate) fn redacted_view(&self) -> AuthorityView {
        AuthorityView {
            installation_uid: self.installation_uid.clone(),
            host_identity: self.host_identity.clone(),
            signing_key_count: self.signing_keys.len(),
            controllers: self.controllers.iter().map(ControllerView::from).collect(),
        }
    }
}

impl fmt::Debug for PreparedAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAuthority")
            .field("installation_uid", &self.installation_uid)
            .field("host_identity", &self.host_identity)
            .field("signing_key_count", &self.signing_keys.len())
            .field("controller_count", &self.controllers.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AuthorityView {
    pub(crate) installation_uid: InstallationUid,
    pub(crate) host_identity: HostIdentity,
    pub(crate) signing_key_count: usize,
    pub(crate) controllers: Vec<ControllerView>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ControllerView {
    pub(crate) subject: CallerSubject,
    pub(crate) assurance: AuthenticationAssurance,
    pub(crate) tenant_count: usize,
    pub(crate) signing_key_count: usize,
    pub(crate) profile_count: usize,
    pub(crate) repository_count: usize,
    pub(crate) workspace_count: usize,
}

impl From<&PreparedController> for ControllerView {
    fn from(value: &PreparedController) -> Self {
        Self {
            subject: value.subject.clone(),
            assurance: value.assurance(),
            tenant_count: value.tenant_ids.len(),
            signing_key_count: value.signing_key_ids.len(),
            profile_count: value.profile_uids.len(),
            repository_count: value.repositories.len(),
            workspace_count: value.workspace_ids.len(),
        }
    }
}

/// Cryptographic and scope evidence that cannot be constructed outside this module.
///
/// This is never lease, session, or execution authority. A future service must
/// perform its separate lifecycle and policy checks before granting authority.
pub(crate) struct VerifiedWorkOrder {
    caller_subject: CallerSubject,
    host_identity: HostIdentity,
    assurance: AuthenticationAssurance,
    attestation_binding: Sha256Digest,
    configuration_digest: Sha256Digest,
    key_id: KeyId,
    signed_message_digest: Sha256Digest,
    authorization: WorkOrderAuthorization,
}

impl VerifiedWorkOrder {
    #[must_use]
    pub(crate) const fn caller_subject(&self) -> &CallerSubject {
        &self.caller_subject
    }

    #[must_use]
    pub(crate) const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    #[must_use]
    pub(crate) const fn host_identity(&self) -> &HostIdentity {
        &self.host_identity
    }

    #[must_use]
    pub(crate) const fn assurance(&self) -> AuthenticationAssurance {
        self.assurance
    }

    #[must_use]
    pub(crate) const fn authorization(&self) -> &WorkOrderAuthorization {
        &self.authorization
    }

    #[must_use]
    pub(crate) const fn signed_message_digest(&self) -> Sha256Digest {
        self.signed_message_digest
    }

    #[must_use]
    pub(crate) fn matches(
        &self,
        authority: &PreparedAuthority,
        caller: &crate::automation::attestation::AuthenticatedCaller,
        authorization: &WorkOrderAuthorization,
        now: &crate::automation::contracts::UtcTimestamp,
    ) -> bool {
        caller.revalidate(authority).is_ok()
            && !now.is_before(&authorization.not_before)
            && now.is_before(&authorization.expires_at)
            && self.configuration_digest == authority.configuration_digest()
            && self.caller_subject == *caller.subject()
            && self.host_identity == *caller.host_identity()
            && self.assurance == caller.assurance()
            && self.attestation_binding == caller.attestation_binding()
            && self.authorization == *authorization
    }
}

impl fmt::Debug for VerifiedWorkOrder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedWorkOrder")
            .field("caller_subject", &self.caller_subject)
            .field("host_identity", &self.host_identity)
            .field("assurance", &self.assurance)
            .field("key_id", &self.key_id)
            .field("signed_message_digest", &self.signed_message_digest)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(super) mod tests;
