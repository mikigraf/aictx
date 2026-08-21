//! Explicit, copy-only migration support for the `aictx` to `ctxlane` rename.
//!
//! This module deliberately has no startup hook. Callers must first inspect a
//! [`MigrationPlan`] and then explicitly execute it. The legacy store is never
//! changed or removed, so it remains available for rollback.

mod filesystem;
mod journal;

use std::{fmt, path::Path};

use crate::{
    Error, Result,
    config::{AppPaths, ProfileLockGuard, acquire_profile_lock},
    model::{Config, MutableState, Profile},
};
use filesystem::{VendorEntry, VendorEntryKind};

/// Counts discovered while inspecting a legacy store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationSummary {
    profiles: usize,
    vendor_files: usize,
    vendor_directories: usize,
    skipped_locks: usize,
}

impl MigrationSummary {
    /// Return the number of configured provider profiles.
    #[must_use]
    pub const fn profile_count(self) -> usize {
        self.profiles
    }

    /// Return the number of regular vendor-state files that will be copied.
    #[must_use]
    pub const fn vendor_file_count(self) -> usize {
        self.vendor_files
    }

    /// Return the number of vendor-state directories that will be copied.
    #[must_use]
    pub const fn vendor_directory_count(self) -> usize {
        self.vendor_directories
    }

    /// Return the number of lock entries that will be deliberately skipped.
    #[must_use]
    pub const fn skipped_lock_count(self) -> usize {
        self.skipped_locks
    }
}

/// The result of a completed migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationReceipt {
    summary: MigrationSummary,
    config_file: std::path::PathBuf,
    state_file: std::path::PathBuf,
}

impl MigrationReceipt {
    /// Return the counts from the executed plan.
    #[must_use]
    pub const fn summary(&self) -> MigrationSummary {
        self.summary
    }

    /// Return the new configuration file path.
    #[must_use]
    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    /// Return the new mutable-state file path.
    #[must_use]
    pub fn state_file(&self) -> &Path {
        &self.state_file
    }
}

/// The outcome of cleaning up an interrupted migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    /// No migration journal was present.
    NothingToRecover,
    /// An incomplete staged or partially committed target was removed.
    RolledBack,
    /// A fully verified target was kept and its journal was finalized.
    Finalized,
}

/// A validated, non-mutating migration plan.
///
/// Constructing a plan reads the complete legacy metadata and vendor-state
/// manifest but does not create a target directory. The plan intentionally has
/// a redacted `Debug` implementation because configuration can contain account
/// hints and credential-store references.
#[derive(Clone)]
pub struct MigrationPlan {
    legacy: AppPaths,
    target: AppPaths,
    source_config_bytes: Vec<u8>,
    source_state_bytes: Vec<u8>,
    migrated_config: Config,
    state: MutableState,
    vendor_entries: Vec<VendorEntry>,
    anchors: Vec<std::path::PathBuf>,
    summary: MigrationSummary,
}

impl fmt::Debug for MigrationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationPlan")
            .field("legacy_config_dir", &self.legacy.config_dir)
            .field("target_config_dir", &self.target.config_dir)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl MigrationPlan {
    /// Inspect and validate an initialized legacy store without changing it.
    ///
    /// The target application directories must not exist. An interrupted
    /// migration must be handled with [`recover_incomplete`] before planning a
    /// new migration.
    pub fn inspect(legacy: &AppPaths, target: &AppPaths) -> Result<Self> {
        filesystem::validate_distinct_layouts(legacy, target)?;
        journal::ensure_no_journal(target)?;
        let anchors = filesystem::target_anchors(target);
        filesystem::validate_target_is_absent(&anchors)?;
        filesystem::validate_target_parents(&anchors, &journal::journal_path(target))?;

        legacy.validate_layout()?;
        let source_config_bytes = filesystem::read_sensitive_bytes(&legacy.config_file)?;
        let source_state_bytes = filesystem::read_sensitive_bytes(&legacy.state_file)?;
        let source_config: Config =
            filesystem::parse_toml(&legacy.config_file, &source_config_bytes)?;
        let state: MutableState = filesystem::parse_toml(&legacy.state_file, &source_state_bytes)?;
        validate_managed_metadata(&source_config, &state, legacy, "legacy")?;

        let mut migrated_config = source_config;
        rewrite_profile_state_directories(&mut migrated_config, target);
        validate_managed_metadata(&migrated_config, &state, target, "migrated")?;

        let (vendor_entries, skipped_locks) =
            filesystem::vendor_manifest(&legacy.data_dir.join("vendor-state"))?;
        let summary = MigrationSummary {
            profiles: migrated_config.profiles.len(),
            vendor_files: vendor_entries
                .iter()
                .filter(|entry| matches!(entry.kind, VendorEntryKind::File(_)))
                .count(),
            vendor_directories: vendor_entries
                .iter()
                .filter(|entry| matches!(entry.kind, VendorEntryKind::Directory))
                .count(),
            skipped_locks,
        };

        Ok(Self {
            legacy: legacy.clone(),
            target: target.clone(),
            source_config_bytes,
            source_state_bytes,
            migrated_config,
            state,
            vendor_entries,
            anchors,
            summary,
        })
    }

    /// Return the inspected migration counts.
    #[must_use]
    pub const fn summary(&self) -> MigrationSummary {
        self.summary
    }

    /// Return the legacy paths that will only be read.
    #[must_use]
    pub const fn legacy_paths(&self) -> &AppPaths {
        &self.legacy
    }

    /// Return the target paths that will be created.
    #[must_use]
    pub const fn target_paths(&self) -> &AppPaths {
        &self.target
    }

    /// Execute this plan by staging a complete copy and committing it.
    ///
    /// A non-secret journal makes interruption recoverable. Configuration is
    /// committed last when it has a separate platform directory, so an
    /// incomplete target never looks initialized. Any ordinary error triggers
    /// a rollback of migration-owned target paths.
    pub fn execute(self) -> Result<MigrationReceipt> {
        // Match the lock order used by profile lifecycle operations and keep
        // all guards alive until the target has been committed and verified.
        let _profile_locks = self.acquire_legacy_profile_locks()?;
        let _metadata_lock = filesystem::acquire_legacy_metadata_lock(&self.legacy)?;
        self.revalidate_source_and_target()?;
        journal::execute(&self)
    }

    fn acquire_legacy_profile_locks(&self) -> Result<Vec<ProfileLockGuard>> {
        self.migrated_config
            .profiles
            .keys()
            .map(|profile_id| {
                acquire_profile_lock(
                    &self
                        .legacy
                        .profile_lock(profile_id.provider(), profile_id.name()),
                    true,
                )
            })
            .collect()
    }

    fn revalidate_source_and_target(&self) -> Result<()> {
        journal::ensure_no_journal(&self.target)?;
        filesystem::validate_target_is_absent(&self.anchors)?;
        self.revalidate_source()
    }

    fn revalidate_source(&self) -> Result<()> {
        let config_bytes = filesystem::read_sensitive_bytes(&self.legacy.config_file)?;
        let state_bytes = filesystem::read_sensitive_bytes(&self.legacy.state_file)?;
        if config_bytes != self.source_config_bytes || state_bytes != self.source_state_bytes {
            return Err(Error::ConfigBusy);
        }
        let (entries, skipped_locks) =
            filesystem::vendor_manifest(&self.legacy.data_dir.join("vendor-state"))?;
        if entries != self.vendor_entries || skipped_locks != self.summary.skipped_locks {
            return Err(Error::ConfigBusy);
        }
        Ok(())
    }
}

/// Return the deterministic journal path for a target layout.
#[must_use]
pub fn migration_journal_path(target: &AppPaths) -> std::path::PathBuf {
    journal::journal_path(target)
}

/// Recover an interrupted migration for the exact supplied path pair.
///
/// A verified migration is finalized and kept. Any earlier phase is rolled
/// back, but only directories carrying this transaction's private owner marker
/// can be removed.
pub fn recover_incomplete(legacy: &AppPaths, target: &AppPaths) -> Result<RecoveryOutcome> {
    journal::recover(legacy, target)
}

fn rewrite_profile_state_directories(config: &mut Config, target: &AppPaths) {
    for (profile_id, profile) in &mut config.profiles {
        let target_state = target.profile_state_dir(profile_id.provider(), profile_id.name());
        match profile {
            Profile::Claude { state_dir, .. } | Profile::Codex { state_dir, .. } => {
                *state_dir = target_state;
            }
        }
    }
}

fn validate_managed_metadata(
    config: &Config,
    state: &MutableState,
    paths: &AppPaths,
    label: &str,
) -> Result<()> {
    config.validate()?;
    state.validate(config)?;
    for (profile_id, profile) in &config.profiles {
        let expected = paths.profile_state_dir(profile_id.provider(), profile_id.name());
        if profile.state_dir() != expected {
            return Err(Error::InvalidConfig(format!(
                "{label} profile `{profile_id}` state_dir must be {}",
                expected.display()
            )));
        }
    }
    Ok(())
}
