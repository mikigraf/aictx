use crate::automation::{authority::PreparedAuthority, contracts::Sha256Digest};

use super::{AttestationError, AuthenticatedCaller};

pub(crate) struct MacosDevelopmentAttestor {
    explicit_development_opt_in: bool,
}

impl MacosDevelopmentAttestor {
    #[must_use]
    pub(crate) const fn new(explicit_development_opt_in: bool) -> Self {
        Self {
            explicit_development_opt_in,
        }
    }

    pub(crate) fn attest(
        &self,
        authority: &PreparedAuthority,
    ) -> Result<AuthenticatedCaller, AttestationError> {
        if !self.explicit_development_opt_in {
            return Err(AttestationError::DevelopmentOptInRequired);
        }
        let mut candidates = authority
            .controllers()
            .iter()
            .filter(|controller| controller.is_macos_development_unqualified());
        let controller = candidates
            .next()
            .filter(|_| candidates.next().is_none())
            .ok_or(AttestationError::CallerAuthenticationFailed)?
            .clone();
        let binding = attestation_binding(authority, controller.subject());
        Ok(AuthenticatedCaller::macos_development(
            authority, controller, binding,
        ))
    }
}

pub(super) fn revalidate(
    caller: &AuthenticatedCaller,
    authority: &PreparedAuthority,
) -> Result<(), AttestationError> {
    if !caller.controller.is_macos_development_unqualified()
        || caller.attestation_binding != attestation_binding(authority, caller.controller.subject())
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(())
}

fn attestation_binding(
    authority: &PreparedAuthority,
    subject: &crate::automation::contracts::CallerSubject,
) -> Sha256Digest {
    let mut material = b"ctxlane.macos-development-attestation/v1\0".to_vec();
    material.extend_from_slice(authority.host_identity().as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(subject.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(authority.configuration_digest().to_string().as_bytes());
    Sha256Digest::hash(material)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;

    use crate::{
        automation::authority::{AuthenticationAssurance, PreparedAuthority},
        config::AppPaths,
        model::InstallationUid,
    };

    use super::*;

    fn authority() -> (TempDir, PreparedAuthority) {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
        fs::create_dir_all(&paths.config_dir)
            .unwrap_or_else(|error| panic!("config directory: {error}"));
        fs::set_permissions(&paths.config_dir, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("config permissions: {error}"));
        let installation = InstallationUid::parse("installation_01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap_or_else(|error| panic!("installation: {error}"));
        let source = super::super::super::authority::tests::valid_macos_config();
        fs::write(paths.automation_authority_config(), source)
            .unwrap_or_else(|error| panic!("write authority: {error}"));
        fs::set_permissions(
            paths.automation_authority_config(),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap_or_else(|error| panic!("authority permissions: {error}"));
        let authority = PreparedAuthority::load(&paths, &installation)
            .unwrap_or_else(|error| panic!("load authority: {error:?}"));
        (temporary, authority)
    }

    #[test]
    fn development_adapter_refuses_by_default_and_is_never_production() {
        let (_temporary, authority) = authority();
        assert!(matches!(
            MacosDevelopmentAttestor::new(false).attest(&authority),
            Err(AttestationError::DevelopmentOptInRequired)
        ));
        let caller = MacosDevelopmentAttestor::new(true)
            .attest(&authority)
            .unwrap_or_else(|error| panic!("development attestation: {error:?}"));
        assert_eq!(
            caller.assurance(),
            AuthenticationAssurance::MacosDevelopmentUnqualified
        );
    }
}
