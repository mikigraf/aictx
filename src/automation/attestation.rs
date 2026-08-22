//! Sealed caller-attestation primitives for an explicit future service.

use std::fmt;

use thiserror::Error;

use crate::automation::{
    authority::{AuthenticationAssurance, PreparedAuthority, PreparedController},
    contracts::{CallerSubject, HostIdentity, Sha256Digest},
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub(crate) use linux::LinuxAttestor;
#[cfg(target_os = "macos")]
#[allow(unused_imports)]
pub(crate) use macos::MacosDevelopmentAttestor;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(unused_imports)]
pub(crate) use unsupported::UnsupportedAttestor;

/// Stable, input-free errors for caller authentication.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum AttestationError {
    #[error("caller authentication failed")]
    CallerAuthenticationFailed,
    #[error("macOS automation requires an explicit unqualified-development opt-in")]
    DevelopmentOptInRequired,
    #[error("automation caller authentication is unsupported on this platform")]
    UnsupportedPlatform,
}

/// An attested connection-opening controller. Construction is platform-private.
///
/// On Linux this value alone must never authorize an individual stream message:
/// a future listener must also obtain per-message credentials and match them to
/// the retained, revalidated process identity.
pub(crate) struct AuthenticatedCaller {
    subject: CallerSubject,
    host_identity: HostIdentity,
    assurance: AuthenticationAssurance,
    attestation_binding: Sha256Digest,
    controller: PreparedController,
    #[cfg(target_os = "linux")]
    process_guard: linux::LinuxProcessGuard,
}

impl AuthenticatedCaller {
    #[must_use]
    pub(crate) const fn subject(&self) -> &CallerSubject {
        &self.subject
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
    pub(crate) const fn attestation_binding(&self) -> Sha256Digest {
        self.attestation_binding
    }

    #[must_use]
    pub(super) const fn controller(&self) -> &PreparedController {
        &self.controller
    }

    pub(super) fn revalidate(&self, authority: &PreparedAuthority) -> Result<(), AttestationError> {
        if self.host_identity != *authority.host_identity()
            || self.controller
                != *authority
                    .controllers()
                    .iter()
                    .find(|controller| controller.subject() == &self.subject)
                    .ok_or(AttestationError::CallerAuthenticationFailed)?
        {
            return Err(AttestationError::CallerAuthenticationFailed);
        }
        #[cfg(target_os = "linux")]
        return linux::revalidate(self, authority);
        #[cfg(target_os = "macos")]
        return macos::revalidate(self, authority);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(AttestationError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    fn linux(
        authority: &PreparedAuthority,
        controller: PreparedController,
        attestation_binding: Sha256Digest,
        process_guard: linux::LinuxProcessGuard,
    ) -> Self {
        Self {
            subject: controller.subject().clone(),
            host_identity: authority.host_identity().clone(),
            assurance: AuthenticationAssurance::LinuxConnectionAttested,
            attestation_binding,
            controller,
            process_guard,
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_development(
        authority: &PreparedAuthority,
        controller: PreparedController,
        attestation_binding: Sha256Digest,
    ) -> Self {
        Self {
            subject: controller.subject().clone(),
            host_identity: authority.host_identity().clone(),
            assurance: AuthenticationAssurance::MacosDevelopmentUnqualified,
            attestation_binding,
            controller,
        }
    }
}

impl fmt::Debug for AuthenticatedCaller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedCaller")
            .field("subject", &self.subject)
            .field("host_identity", &self.host_identity)
            .field("assurance", &self.assurance)
            .field("attestation_binding", &self.attestation_binding)
            .finish_non_exhaustive()
    }
}
