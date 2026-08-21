use crate::brand::{CURRENT_PRODUCT_LABEL, LEGACY_PRODUCT_LABEL, TARGET_PRODUCT_LABEL};

/// The platform directory identity used to locate application metadata.
///
/// Values are intentionally constructed only inside this module. This keeps
/// application names trusted when they are passed to the platform directory
/// resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppIdentity {
    qualifier: &'static str,
    organization: &'static str,
    application: &'static str,
}

impl AppIdentity {
    const fn new(
        qualifier: &'static str,
        organization: &'static str,
        application: &'static str,
    ) -> Self {
        Self {
            qualifier,
            organization,
            application,
        }
    }

    /// Return the reverse-domain qualifier used by the platform directory API.
    #[must_use]
    pub const fn qualifier(self) -> &'static str {
        self.qualifier
    }

    /// Return the publisher name used by the platform directory API.
    #[must_use]
    pub const fn organization(self) -> &'static str {
        self.organization
    }

    /// Return the application name used by the platform directory API.
    #[must_use]
    pub const fn application(self) -> &'static str {
        self.application
    }
}

/// The directory identity used by released `aictx` versions.
pub const LEGACY_AICTX: AppIdentity = AppIdentity::new("dev", "Cloudsail", LEGACY_PRODUCT_LABEL);

/// The directory identity intended for the `ctxlane` migration.
pub const TARGET_CTXLANE: AppIdentity = AppIdentity::new("dev", "Cloudsail", TARGET_PRODUCT_LABEL);

/// The directory identity used by the current executable.
///
/// Keep this pointed at the legacy identity until migration behavior is ready.
pub const CURRENT_APPLICATION: AppIdentity =
    AppIdentity::new("dev", "Cloudsail", CURRENT_PRODUCT_LABEL);

#[cfg(test)]
mod tests {
    use super::{CURRENT_APPLICATION, LEGACY_AICTX, TARGET_CTXLANE};

    #[test]
    fn application_identities_keep_the_legacy_label_stable() {
        assert_eq!(LEGACY_AICTX.application(), "aictx");
        assert_eq!(TARGET_CTXLANE.application(), "ctxlane");
        assert_eq!(CURRENT_APPLICATION, LEGACY_AICTX);
    }
}
