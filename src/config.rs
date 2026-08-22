use std::{
    fs,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use serde::de::DeserializeOwned;

use crate::{
    Error, Result,
    binary::is_in_current_repository,
    identity::{AppIdentity, CURRENT_APPLICATION},
    model::{Config, MutableState, Name, ProfileUid, Provider},
};

mod automation_paths;
mod storage;
mod upgrade;

pub use storage::write_secure_text;
pub(crate) use storage::{
    OrderedProfileLocks, ProfileLockGuard, acquire_ordered_profile_locks, acquire_profile_lock,
};
use storage::{acquire_exclusive, acquire_shared, write_toml};

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub config_file: PathBuf,
    pub state_file: PathBuf,
    metadata_lock: PathBuf,
    config_lock: PathBuf,
    state_lock: PathBuf,
}

impl AppPaths {
    pub fn discover(explicit_root: Option<&Path>) -> Result<Self> {
        Self::discover_for(CURRENT_APPLICATION, explicit_root)
    }

    /// Discover platform paths for an explicit application identity.
    ///
    /// An explicit root is independent of the application identity. This lets
    /// callers preserve `--root` behavior while inspecting legacy and target
    /// default paths during an application-name migration.
    pub fn discover_for(identity: AppIdentity, explicit_root: Option<&Path>) -> Result<Self> {
        if let Some(root) = explicit_root {
            let root = root.to_path_buf();
            if !root.is_absolute() {
                return Err(Error::InvalidConfig(format!(
                    "--root must be absolute: {}",
                    root.display()
                )));
            }
            reject_relative_path_components("--root", &root)?;
            reject_repository_override("--root", &root)?;
            return Ok(Self::for_root(root));
        }

        let project = ProjectDirs::from(
            identity.qualifier(),
            identity.organization(),
            identity.application(),
        )
        .ok_or_else(|| {
            Error::InvalidConfig("could not determine platform application directories".to_owned())
        })?;

        let config_dir = project.config_dir().to_path_buf();
        let data_dir = project.data_dir().to_path_buf();
        let state_dir = project
            .state_dir()
            .map_or_else(|| data_dir.join("state"), Path::to_path_buf);

        Self::from_dirs(config_dir, data_dir, state_dir)
    }

    #[must_use]
    pub fn for_root(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        let config_dir = root.join("config");
        let data_dir = root.join("data");
        let state_dir = root.join("state");
        Self {
            config_file: config_dir.join("config.toml"),
            state_file: state_dir.join("state.toml"),
            metadata_lock: state_dir.join("metadata.lock"),
            config_lock: config_dir.join("config.lock"),
            state_lock: state_dir.join("state.lock"),
            config_dir,
            data_dir,
            state_dir,
        }
    }

    fn from_dirs(config_dir: PathBuf, data_dir: PathBuf, state_dir: PathBuf) -> Result<Self> {
        for (label, path) in [
            ("config", &config_dir),
            ("data", &data_dir),
            ("state", &state_dir),
        ] {
            if !path.is_absolute() {
                return Err(Error::InvalidConfig(format!(
                    "{label} directory must be absolute: {}",
                    path.display()
                )));
            }
            reject_relative_path_components(label, path)?;
            reject_repository_override(label, path)?;
        }

        Ok(Self {
            config_file: config_dir.join("config.toml"),
            state_file: state_dir.join("state.toml"),
            metadata_lock: state_dir.join("metadata.lock"),
            config_lock: config_dir.join("config.lock"),
            state_lock: state_dir.join("state.lock"),
            config_dir,
            data_dir,
            state_dir,
        })
    }

    pub fn ensure_layout(&self) -> Result<()> {
        for directory in [&self.config_dir, &self.data_dir, &self.state_dir] {
            ensure_secure_directory(directory)?;
        }
        ensure_secure_directory(&self.data_dir.join("vendor-state"))?;
        ensure_secure_directory(&self.state_dir.join("profile-locks"))?;
        Ok(())
    }

    /// Validate the complete application layout without creating or changing it.
    pub fn validate_layout(&self) -> Result<()> {
        for directory in [
            &self.config_dir,
            &self.data_dir,
            &self.state_dir,
            &self.data_dir.join("vendor-state"),
            &self.state_dir.join("profile-locks"),
        ] {
            validate_secure_directory(directory)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn profile_state_dir(&self, provider: Provider, name: &Name) -> PathBuf {
        self.profile_state_root(provider).join(name.as_str())
    }

    #[must_use]
    pub fn profile_state_root(&self, provider: Provider) -> PathBuf {
        self.data_dir
            .join("vendor-state")
            .join(provider.to_string())
    }

    #[must_use]
    pub fn is_managed_profile_state_dir(&self, provider: Provider, path: &Path) -> bool {
        path.parent() == Some(self.profile_state_root(provider).as_path())
            && path.file_name().is_some_and(valid_profile_state_leaf)
    }

    #[must_use]
    pub fn profile_lock(&self, provider: Provider, name: &Name) -> PathBuf {
        self.state_dir.join("profile-locks").join(format!(
            "{provider}-{}.lock",
            name.as_str().to_ascii_lowercase()
        ))
    }

    /// Immutable lifecycle lock shared by profile mutation and execution paths.
    #[must_use]
    pub fn profile_lifecycle_lock(&self, profile_uid: &ProfileUid) -> PathBuf {
        self.state_dir
            .join("profile-locks")
            .join(format!("{}-lifecycle.lock", profile_uid.as_str()))
    }

    /// Immutable mutable-vendor-home lock held exclusively by every vendor operation.
    #[must_use]
    pub fn profile_resource_lock(&self, profile_uid: &ProfileUid) -> PathBuf {
        self.state_dir
            .join("profile-locks")
            .join(format!("{}-resource.lock", profile_uid.as_str()))
    }

    /// Private state root used only by an explicitly opened automation service.
    ///
    /// This is a pure path derivation. It does not inspect or create the path.
    #[must_use]
    pub fn automation_state_dir(&self) -> PathBuf {
        self.state_dir.join("automation")
    }

    /// Durable automation lease-store path, without touching the filesystem.
    #[must_use]
    pub fn automation_lease_store(&self) -> PathBuf {
        self.automation_state_dir().join("lease-store.sqlite3")
    }

    /// Lifetime service-lock path, without touching the filesystem.
    #[must_use]
    pub fn automation_service_lock(&self) -> PathBuf {
        self.automation_state_dir().join("service.lock")
    }
}

fn valid_profile_state_leaf(leaf: &std::ffi::OsStr) -> bool {
    leaf.to_str()
        .is_some_and(|value| Name::parse(value.to_owned()).is_ok())
}

fn reject_repository_override(variable: &str, path: &Path) -> Result<()> {
    if is_in_current_repository(path) {
        return Err(Error::PolicyRefused(format!(
            "{variable} must not point inside the current Git worktree ({})",
            path.display()
        )));
    }
    Ok(())
}

fn reject_relative_path_components(label: &str, path: &Path) -> Result<()> {
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(Error::InvalidConfig(format!(
            "{label} must not contain `.` or `..` path components: {}",
            path.display()
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct MetadataStore {
    paths: AppPaths,
}

impl MetadataStore {
    #[must_use]
    pub const fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    #[must_use]
    pub const fn paths(&self) -> &AppPaths {
        &self.paths
    }

    pub fn initialize(&self) -> Result<bool> {
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_exclusive(&self.paths.metadata_lock)?;
        let _config_lock = acquire_exclusive(&self.paths.config_lock)?;
        let _state_lock = acquire_exclusive(&self.paths.state_lock)?;
        if self.paths.config_file.exists() {
            let mut decoded = read_config(&self.paths.config_file)?;
            let state = if self.paths.state_file.exists() {
                read_toml(&self.paths.state_file)?
            } else {
                MutableState::default()
            };
            let config = &decoded.config;
            self.validate_config(config)?;
            state.validate(config)?;
            persist_config_upgrade(&self.paths.config_file, &mut decoded)?;
            if !self.paths.state_file.exists() {
                write_toml(&self.paths.state_file, &state)?;
            }
            return Ok(false);
        }

        let config = Config::new()?;
        write_toml(&self.paths.config_file, &config)?;
        if !self.paths.state_file.exists() {
            write_toml(&self.paths.state_file, &MutableState::default())?;
        }
        Ok(true)
    }

    pub fn load_config(&self) -> Result<Config> {
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_exclusive(&self.paths.metadata_lock)?;
        let _lock = acquire_exclusive(&self.paths.config_lock)?;
        let mut decoded = read_config(&self.paths.config_file)?;
        self.validate_config(&decoded.config)?;
        persist_config_upgrade(&self.paths.config_file, &mut decoded)?;
        Ok(decoded.config)
    }

    /// Read configuration for a diagnostic command without creating locks or directories.
    ///
    /// The result is only a point-in-time diagnostic snapshot; normal operations use the
    /// coordinated metadata locks above.
    pub fn load_config_for_diagnostics(&self) -> Result<Config> {
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }
        let decoded = read_config(&self.paths.config_file)?;
        self.validate_config(&decoded.config)?;
        Ok(decoded.config)
    }

    pub fn load_state(&self, config: &Config) -> Result<MutableState> {
        if !config.is_authoritative() {
            return Err(Error::InvalidConfig(
                "a projected legacy configuration is diagnostic-only".to_owned(),
            ));
        }
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_shared(&self.paths.metadata_lock)?;
        let _lock = acquire_shared(&self.paths.state_lock)?;
        let state = if self.paths.state_file.exists() {
            read_toml(&self.paths.state_file)?
        } else {
            MutableState::default()
        };
        state.validate(config)?;
        Ok(state)
    }

    pub fn load_metadata(&self) -> Result<(Config, MutableState)> {
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_exclusive(&self.paths.metadata_lock)?;
        let _config_lock = acquire_exclusive(&self.paths.config_lock)?;
        let _state_lock = acquire_shared(&self.paths.state_lock)?;
        let mut decoded = read_config(&self.paths.config_file)?;
        self.validate_config(&decoded.config)?;
        let state = if self.paths.state_file.exists() {
            read_toml(&self.paths.state_file)?
        } else {
            MutableState::default()
        };
        state.validate(&decoded.config)?;
        persist_config_upgrade(&self.paths.config_file, &mut decoded)?;
        Ok((decoded.config, state))
    }

    pub fn update_config<T>(&self, update: impl FnOnce(&mut Config) -> Result<T>) -> Result<T> {
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_exclusive(&self.paths.metadata_lock)?;
        let _config_lock = acquire_exclusive(&self.paths.config_lock)?;
        let _state_lock = acquire_shared(&self.paths.state_lock)?;
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }
        let decoded = read_config(&self.paths.config_file)?;
        let mut config = decoded.config;
        self.validate_config(&config)?;
        let state = if self.paths.state_file.exists() {
            read_toml(&self.paths.state_file)?
        } else {
            MutableState::default()
        };
        state.validate(&config)?;
        let output = update(&mut config)?;
        self.validate_config(&config)?;
        state.validate(&config)?;
        config.mark_persisted();
        write_toml(&self.paths.config_file, &config)?;
        Ok(output)
    }

    pub fn update_state<T>(
        &self,
        update: impl FnOnce(&Config, &mut MutableState) -> Result<T>,
    ) -> Result<T> {
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_exclusive(&self.paths.metadata_lock)?;
        let _config_lock = acquire_exclusive(&self.paths.config_lock)?;
        let _state_lock = acquire_exclusive(&self.paths.state_lock)?;
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }
        let mut decoded = read_config(&self.paths.config_file)?;
        self.validate_config(&decoded.config)?;
        let mut state = if self.paths.state_file.exists() {
            read_toml(&self.paths.state_file)?
        } else {
            MutableState::default()
        };
        state.validate(&decoded.config)?;
        let output = update(&decoded.config, &mut state)?;
        state.validate(&decoded.config)?;
        persist_config_upgrade(&self.paths.config_file, &mut decoded)?;
        write_toml(&self.paths.state_file, &state)?;
        Ok(output)
    }

    pub fn update_metadata<T>(
        &self,
        update: impl FnOnce(&mut Config, &mut MutableState) -> Result<T>,
    ) -> Result<T> {
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_exclusive(&self.paths.metadata_lock)?;
        let _config_lock = acquire_exclusive(&self.paths.config_lock)?;
        let _state_lock = acquire_exclusive(&self.paths.state_lock)?;
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }

        let decoded = read_config(&self.paths.config_file)?;
        let migrated = decoded.migrated;
        let mut config = decoded.config;
        self.validate_config(&config)?;
        let mut state = if self.paths.state_file.exists() {
            read_toml(&self.paths.state_file)?
        } else {
            MutableState::default()
        };
        state.validate(&config)?;

        let original_config = config.clone();
        let original_state = state.clone();
        let output = update(&mut config, &mut state)?;
        self.validate_config(&config)?;
        state.validate(&config)?;
        if migrated || config != original_config {
            config.mark_persisted();
            write_toml(&self.paths.config_file, &config)?;
        }
        if state != original_state {
            write_toml(&self.paths.state_file, &state)?;
        }
        Ok(output)
    }

    fn validate_config(&self, config: &Config) -> Result<()> {
        config.validate()?;
        for (profile_id, profile) in &config.profiles {
            if !self
                .paths
                .is_managed_profile_state_dir(profile_id.provider(), profile.state_dir())
            {
                return Err(Error::InvalidConfig(format!(
                    "profile `{profile_id}` state_dir must be the managed directory's immediate child beneath {}",
                    self.paths
                        .profile_state_root(profile_id.provider())
                        .display()
                )));
            }
        }
        Ok(())
    }
}

pub fn ensure_secure_directory(path: &Path) -> Result<()> {
    validate_absolute_sensitive_path(path)?;
    validate_trusted_path_chain(path, LeafOwnership::CurrentUser)?;

    let mut missing = Vec::new();
    let mut cursor = Some(path);
    while let Some(candidate) = cursor {
        match fs::symlink_metadata(candidate) {
            Ok(_) => break,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
                cursor = candidate.parent();
            }
            Err(source) => {
                return Err(Error::ReadFile {
                    path: candidate.to_path_buf(),
                    source,
                });
            }
        }
    }

    for directory in missing.iter().rev() {
        #[cfg(unix)]
        let mut builder = fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            builder.mode(0o700);
        }
        match builder.create(directory) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(Error::CreateDir {
                    path: directory.clone(),
                    source,
                });
            }
        }
        validate_trusted_path_chain(directory, LeafOwnership::CurrentUser)?;
        validate_secure_directory_leaf(directory)?;
    }

    validate_secure_directory(path)
}

pub fn validate_secure_directory(path: &Path) -> Result<()> {
    validate_absolute_sensitive_path(path)?;
    validate_trusted_path_chain(path, LeafOwnership::CurrentUser)?;
    validate_secure_directory_leaf(path)
}

pub fn validate_sensitive_file(path: &Path) -> Result<()> {
    validate_absolute_sensitive_path(path)?;
    validate_trusted_path_chain(path, LeafOwnership::CurrentUser)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(Error::PolicyRefused(format!(
            "{} is not a regular file",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(Error::PolicyRefused(format!(
                "{} is not owned by the current user",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::PolicyRefused(format!(
                "{} contains sensitive state and must have mode 0600 or stricter",
                path.display()
            )));
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeafOwnership {
    CurrentUser,
    CurrentUserOrRoot,
}

pub(crate) fn validate_trusted_path_chain(
    path: &Path,
    leaf_ownership: LeafOwnership,
) -> Result<()> {
    validate_absolute_sensitive_path(path)?;

    #[cfg(not(unix))]
    let _ = leaf_ownership;

    let mut is_leaf = true;
    for candidate in path.ancestors() {
        let metadata = match fs::symlink_metadata(candidate) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                is_leaf = false;
                continue;
            }
            Err(source) => {
                return Err(Error::ReadFile {
                    path: candidate.to_path_buf(),
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(Error::PolicyRefused(format!(
                "refusing symlinked security-sensitive path component {}",
                candidate.display()
            )));
        }
        if !is_leaf && !metadata.is_dir() {
            return Err(Error::PolicyRefused(format!(
                "security-sensitive path ancestor {} is not a directory",
                candidate.display()
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let current_uid = rustix::process::getuid().as_raw();
            let owner = metadata.uid();
            let mode = metadata.permissions().mode();
            let owner_is_allowed = owner == current_uid
                || (leaf_ownership == LeafOwnership::CurrentUserOrRoot && is_leaf && owner == 0);
            if is_leaf && !owner_is_allowed {
                return Err(Error::PolicyRefused(format!(
                    "{} is not owned by the current user{}",
                    candidate.display(),
                    if leaf_ownership == LeafOwnership::CurrentUserOrRoot {
                        " or root"
                    } else {
                        ""
                    }
                )));
            }
            if is_leaf && mode & 0o022 != 0 {
                return Err(Error::PolicyRefused(format!(
                    "security-sensitive path {} is writable by group or other users",
                    candidate.display()
                )));
            }

            if !is_leaf {
                if owner == 0 {
                    let writable_by_others = mode & 0o022 != 0;
                    let sticky = mode & 0o1000 != 0;
                    if writable_by_others && !sticky {
                        return Err(Error::PolicyRefused(format!(
                            "root-owned path ancestor {} is writable by group or other users without the sticky bit",
                            candidate.display()
                        )));
                    }
                    break;
                } else if owner == current_uid {
                    if mode & 0o022 != 0 {
                        return Err(Error::PolicyRefused(format!(
                            "security-sensitive path ancestor {} is writable by group or other users",
                            candidate.display()
                        )));
                    }
                } else {
                    return Err(Error::PolicyRefused(format!(
                        "security-sensitive path ancestor {} is owned by another user",
                        candidate.display()
                    )));
                }
            }
        }

        is_leaf = false;
    }
    Ok(())
}

fn validate_absolute_sensitive_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::PolicyRefused(format!(
            "security-sensitive path must be absolute: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_secure_directory_leaf(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(Error::PolicyRefused(format!(
            "refusing symlinked security-sensitive path {}",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(Error::PolicyRefused(format!(
            "{} is not a directory",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(Error::PolicyRefused(format!(
                "{} is not owned by the current user",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::PolicyRefused(format!(
                "{} must not be accessible by group or other users (expected mode 0700)",
                path.display()
            )));
        }
    }

    Ok(())
}

fn read_toml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    validate_sensitive_file(path)?;
    let text = fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| Error::ParseToml {
        path: path.to_path_buf(),
        source,
    })
}

fn read_config(path: &Path) -> Result<upgrade::DecodedConfig> {
    validate_sensitive_file(path)?;
    let text = fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    upgrade::decode(path, &text)
}

fn persist_config_upgrade(path: &Path, decoded: &mut upgrade::DecodedConfig) -> Result<()> {
    if decoded.migrated {
        decoded.config.mark_persisted();
        write_toml(path, &decoded.config)?;
        decoded.migrated = false;
    }
    Ok(())
}

pub(crate) fn decode_config_for_migration(
    path: &Path,
    bytes: &[u8],
    installation_uid: Option<&crate::model::InstallationUid>,
) -> Result<Config> {
    let redacted = || {
        Error::InvalidConfig(format!(
            "failed to parse TOML metadata in {}; parser details and input were redacted",
            path.display()
        ))
    };
    let text = std::str::from_utf8(bytes).map_err(|_| redacted())?;
    upgrade::decode_with_installation_uid(path, text, installation_uid.cloned())
        .map(|decoded| decoded.config)
        .map_err(|_| redacted())
}

pub(crate) fn expected_legacy_v1_target_config(
    source_path: &Path,
    bytes: &[u8],
    target: &AppPaths,
) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        Error::InvalidConfig(format!(
            "failed to parse TOML metadata in {}; parser details and input were redacted",
            source_path.display()
        ))
    })?;
    upgrade::expected_legacy_v1_target_config(source_path, text, target).map_err(|_| {
        Error::InvalidConfig(format!(
            "failed to parse TOML metadata in {}; parser details and input were redacted",
            source_path.display()
        ))
    })
}

#[cfg(test)]
#[path = "config/tests.rs"]
mod tests;
