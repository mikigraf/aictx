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
pub const LEGACY_AICTX: AppIdentity = AppIdentity::new("dev", "Cloudsail", "aictx");

/// The directory identity intended for the `ctxlane` migration.
pub const TARGET_CTXLANE: AppIdentity = AppIdentity::new("dev", "Cloudsail", "ctxlane");

/// The directory identity used by the current executable.
///
/// Keep this pointed at the legacy identity until migration behavior is ready.
pub const CURRENT_APPLICATION: AppIdentity = LEGACY_AICTX;
