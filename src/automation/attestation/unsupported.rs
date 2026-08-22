use crate::automation::authority::PreparedAuthority;

use super::{AttestationError, AuthenticatedCaller};

pub(crate) struct UnsupportedAttestor;

impl UnsupportedAttestor {
    pub(crate) fn attest(
        _authority: &PreparedAuthority,
    ) -> Result<AuthenticatedCaller, AttestationError> {
        Err(AttestationError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        automation::authority::{AuthorityError, PreparedAuthority},
        config::AppPaths,
        model::InstallationUid,
    };

    #[test]
    fn unsupported_authority_load_is_zero_filesystem() {
        let untouched = Path::new("/must-not-be-read-or-created");
        let paths = AppPaths::for_root(untouched);
        let installation = InstallationUid::parse("installation_01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap_or_else(|error| panic!("installation: {error}"));
        assert!(matches!(
            PreparedAuthority::load(&paths, &installation),
            Err(AuthorityError::UnsupportedPlatform)
        ));
        assert!(!untouched.exists());
    }
}
