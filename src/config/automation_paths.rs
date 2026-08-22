#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;

use super::AppPaths;

impl AppPaths {
    /// Operator-owned automation authority configuration, without filesystem access.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[must_use]
    pub(crate) fn automation_authority_config(&self) -> PathBuf {
        self.config_dir.join("automation-authority.toml")
    }
}
