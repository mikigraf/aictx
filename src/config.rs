use std::{
    fs,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use directories::ProjectDirs;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    Error, Result,
    binary::is_in_current_repository,
    identity::{AppIdentity, CURRENT_APPLICATION},
    model::{Config, MutableState, Name, Provider},
};

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
        self.data_dir
            .join("vendor-state")
            .join(provider.to_string())
            .join(name.as_str())
    }

    #[must_use]
    pub fn profile_lock(&self, provider: Provider, name: &Name) -> PathBuf {
        self.state_dir.join("profile-locks").join(format!(
            "{provider}-{}.lock",
            name.as_str().to_ascii_lowercase()
        ))
    }
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
        let _lock = acquire_exclusive(&self.paths.config_lock)?;
        if self.paths.config_file.exists() {
            let config: Config = read_toml(&self.paths.config_file)?;
            self.validate_config(&config)?;
            return Ok(false);
        }

        let config = Config::default();
        write_toml(&self.paths.config_file, &config)?;
        let _state_lock = acquire_exclusive(&self.paths.state_lock)?;
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
        let _metadata_lock = acquire_shared(&self.paths.metadata_lock)?;
        let _lock = acquire_shared(&self.paths.config_lock)?;
        let config: Config = read_toml(&self.paths.config_file)?;
        self.validate_config(&config)?;
        Ok(config)
    }

    /// Read configuration for a diagnostic command without creating locks or directories.
    ///
    /// The result is only a point-in-time diagnostic snapshot; normal operations use the
    /// coordinated metadata locks above.
    pub fn load_config_for_diagnostics(&self) -> Result<Config> {
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }
        let config: Config = read_toml(&self.paths.config_file)?;
        self.validate_config(&config)?;
        Ok(config)
    }

    pub fn load_state(&self, config: &Config) -> Result<MutableState> {
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
        let _metadata_lock = acquire_shared(&self.paths.metadata_lock)?;
        let _config_lock = acquire_shared(&self.paths.config_lock)?;
        let _state_lock = acquire_shared(&self.paths.state_lock)?;
        let config: Config = read_toml(&self.paths.config_file)?;
        self.validate_config(&config)?;
        let state = if self.paths.state_file.exists() {
            read_toml(&self.paths.state_file)?
        } else {
            MutableState::default()
        };
        state.validate(&config)?;
        Ok((config, state))
    }

    pub fn update_config<T>(&self, update: impl FnOnce(&mut Config) -> Result<T>) -> Result<T> {
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_exclusive(&self.paths.metadata_lock)?;
        let _config_lock = acquire_exclusive(&self.paths.config_lock)?;
        let _state_lock = acquire_shared(&self.paths.state_lock)?;
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }
        let mut config: Config = read_toml(&self.paths.config_file)?;
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
        write_toml(&self.paths.config_file, &config)?;
        Ok(output)
    }

    pub fn update_state<T>(
        &self,
        update: impl FnOnce(&Config, &mut MutableState) -> Result<T>,
    ) -> Result<T> {
        self.paths.ensure_layout()?;
        let _metadata_lock = acquire_exclusive(&self.paths.metadata_lock)?;
        let _config_lock = acquire_shared(&self.paths.config_lock)?;
        let _state_lock = acquire_exclusive(&self.paths.state_lock)?;
        if !self.paths.config_file.exists() {
            return Err(Error::NotInitialized);
        }
        let config: Config = read_toml(&self.paths.config_file)?;
        self.validate_config(&config)?;
        let mut state = if self.paths.state_file.exists() {
            read_toml(&self.paths.state_file)?
        } else {
            MutableState::default()
        };
        state.validate(&config)?;
        let output = update(&config, &mut state)?;
        state.validate(&config)?;
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

        let mut config: Config = read_toml(&self.paths.config_file)?;
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
        if config != original_config {
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
            let expected = self
                .paths
                .profile_state_dir(profile_id.provider(), profile_id.name());
            if profile.state_dir() != expected {
                return Err(Error::InvalidConfig(format!(
                    "profile `{profile_id}` state_dir must be the managed directory {}",
                    expected.display()
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

fn write_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if path.exists() {
        validate_sensitive_file(path)?;
    }
    let text = toml::to_string_pretty(value)?;
    write_secure_text(path, &format!("{text}\n"))
}

pub fn write_secure_text(path: &Path, text: &str) -> Result<()> {
    validate_absolute_sensitive_path(path)?;
    validate_trusted_path_chain(path, LeafOwnership::CurrentUser)?;
    match fs::symlink_metadata(path) {
        Ok(_) => validate_sensitive_file(path)?,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::ReadFile {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let options = AtomicOpenOptions::new();

    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = options;
        options.mode(0o600);
        options
    };

    let mut file = options.open(path).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(text.as_bytes())
        .map_err(|source| Error::WriteFile {
            path: path.to_path_buf(),
            source,
        })?;
    file.commit().map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            Error::WriteFile {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }

    validate_sensitive_file(path)
}

fn lock_file(path: &Path) -> Result<File> {
    validate_absolute_sensitive_path(path)?;
    validate_trusted_path_chain(path, LeafOwnership::CurrentUser)?;
    match fs::symlink_metadata(path) {
        Ok(_) => validate_sensitive_file(path)?,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::ReadFile {
                path: path.to_path_buf(),
                source,
            });
        }
    }

    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    let file = options.open(path).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            Error::WriteFile {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }

    validate_sensitive_file(path)?;
    Ok(file)
}

fn acquire_exclusive(path: &Path) -> Result<File> {
    let file = lock_file(path)?;
    file.lock().map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(file)
}

fn acquire_shared(path: &Path) -> Result<File> {
    let file = lock_file(path)?;
    file.lock_shared().map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(file)
}

pub(crate) struct ProfileLockGuard {
    _file: File,
}

pub(crate) fn acquire_profile_lock(path: &Path, exclusive: bool) -> Result<ProfileLockGuard> {
    let file = lock_file(path)?;
    let result = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    result.map_err(|_| {
        Error::PolicyRefused(format!("profile is busy (lock file {})", path.display()))
    })?;
    Ok(ProfileLockGuard { _file: file })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Barrier},
        thread,
    };

    use tempfile::TempDir;

    use super::*;
    use crate::{
        identity::{LEGACY_AICTX, TARGET_CTXLANE},
        model::{
            BillingDomain, ClaudeAuth, CodexAuth, CodexCredentialStore, Context, Profile, ProfileId,
        },
    };

    fn assert_same_paths(left: &AppPaths, right: &AppPaths) {
        assert_eq!(left.config_dir, right.config_dir);
        assert_eq!(left.data_dir, right.data_dir);
        assert_eq!(left.state_dir, right.state_dir);
        assert_eq!(left.config_file, right.config_file);
        assert_eq!(left.state_file, right.state_file);
        assert_eq!(left.metadata_lock, right.metadata_lock);
        assert_eq!(left.config_lock, right.config_lock);
        assert_eq!(left.state_lock, right.state_lock);
    }

    fn assert_matches_platform_identity(paths: &AppPaths, identity: AppIdentity) {
        let project = ProjectDirs::from(
            identity.qualifier(),
            identity.organization(),
            identity.application(),
        )
        .unwrap_or_else(|| panic!("platform application directories should be available"));
        let data_dir = project.data_dir().to_path_buf();
        let state_dir = project
            .state_dir()
            .map_or_else(|| data_dir.join("state"), Path::to_path_buf);

        assert_eq!(paths.config_dir, project.config_dir());
        assert_eq!(paths.data_dir, data_dir);
        assert_eq!(paths.state_dir, state_dir);
    }

    #[test]
    fn default_discovery_uses_the_legacy_application_identity() {
        let current = AppPaths::discover(None)
            .unwrap_or_else(|error| panic!("discover current paths: {error}"));
        let legacy = AppPaths::discover_for(LEGACY_AICTX, None)
            .unwrap_or_else(|error| panic!("discover legacy paths: {error}"));

        assert_same_paths(&current, &legacy);
        assert_matches_platform_identity(&current, LEGACY_AICTX);
    }

    #[test]
    fn discovery_supports_legacy_and_target_platform_identities() {
        assert_eq!(LEGACY_AICTX.qualifier(), "dev");
        assert_eq!(LEGACY_AICTX.organization(), "Cloudsail");
        assert_eq!(LEGACY_AICTX.application(), "aictx");
        assert_eq!(TARGET_CTXLANE.qualifier(), "dev");
        assert_eq!(TARGET_CTXLANE.organization(), "Cloudsail");
        assert_eq!(TARGET_CTXLANE.application(), "ctxlane");

        let legacy = AppPaths::discover_for(LEGACY_AICTX, None)
            .unwrap_or_else(|error| panic!("discover legacy paths: {error}"));
        let target = AppPaths::discover_for(TARGET_CTXLANE, None)
            .unwrap_or_else(|error| panic!("discover target paths: {error}"));

        assert_matches_platform_identity(&legacy, LEGACY_AICTX);
        assert_matches_platform_identity(&target, TARGET_CTXLANE);
        assert_ne!(legacy.config_dir, target.config_dir);
        assert_ne!(legacy.data_dir, target.data_dir);
        assert_ne!(legacy.state_dir, target.state_dir);
    }

    #[test]
    fn explicit_root_is_independent_of_application_identity() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temporary.path().join("explicit-root");
        let legacy = AppPaths::discover_for(LEGACY_AICTX, Some(&root))
            .unwrap_or_else(|error| panic!("discover legacy paths: {error}"));
        let target = AppPaths::discover_for(TARGET_CTXLANE, Some(&root))
            .unwrap_or_else(|error| panic!("discover target paths: {error}"));

        assert_same_paths(&legacy, &target);
        assert_same_paths(&legacy, &AppPaths::for_root(root));
    }

    #[test]
    fn initialize_is_idempotent_and_secure() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::for_root(temporary.path().join("aictx"));
        let store = MetadataStore::new(paths.clone());
        assert!(store.initialize().is_ok());
        assert!(matches!(store.initialize(), Ok(false)));
        assert!(store.load_config().is_ok());
        assert!(paths.config_file.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&paths.config_file)
                .unwrap_or_else(|error| panic!("metadata: {error}"))
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn update_revalidates_before_commit() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = MetadataStore::new(AppPaths::for_root(temporary.path().join("aictx")));
        assert!(store.initialize().is_ok());
        let result = store.update_config(|config| {
            config.settings.telemetry = true;
            Ok(())
        });
        assert!(result.is_err());
        let config = store
            .load_config()
            .unwrap_or_else(|error| panic!("config remains readable: {error}"));
        assert!(!config.settings.telemetry);
    }

    #[test]
    fn metadata_store_rejects_non_managed_profile_state_directory() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::for_root(temporary.path().join("aictx"));
        let store = MetadataStore::new(paths.clone());
        store
            .initialize()
            .unwrap_or_else(|error| panic!("initialize: {error}"));
        let mut config = store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"));
        let name = Name::parse("work").unwrap_or_else(|error| panic!("name: {error}"));
        config.profiles.insert(
            ProfileId::new(Provider::Codex, name),
            Profile::Codex {
                billing_domain: BillingDomain::ChatgptSubscription,
                auth: CodexAuth::ChatgptOauth,
                state_dir: paths.config_dir.clone(),
                secret_ref: None,
                account_hint: None,
                expected_workspace_id: None,
                credential_store: CodexCredentialStore::File,
                trusted_runners_only: false,
            },
        );
        write_toml(&paths.config_file, &config)
            .unwrap_or_else(|error| panic!("write hand-edited config: {error}"));

        let error = match store.load_config() {
            Err(error) => error.to_string(),
            Ok(_) => panic!("non-managed state directory should be rejected"),
        };
        assert!(error.contains("state_dir must be the managed directory"));
    }

    #[test]
    fn derived_application_directories_inside_a_repository_are_rejected() {
        let cwd = std::env::current_dir().unwrap_or_else(|error| panic!("current dir: {error}"));
        if !cwd
            .ancestors()
            .any(|ancestor| ancestor.join(".git").exists())
        {
            return;
        }
        let error = match AppPaths::from_dirs(
            cwd.join(".test-config"),
            cwd.join(".test-data"),
            cwd.join(".test-state"),
        ) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("repository-derived application paths should be rejected"),
        };
        assert!(error.contains("must not point inside the current Git worktree"));
    }

    #[test]
    fn explicit_root_rejects_parent_components_before_missing_path_resolution() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temporary
            .path()
            .join("missing")
            .join("..")
            .join("repository")
            .join(".aictx");
        let Err(error) = AppPaths::discover(Some(&root)) else {
            panic!("root containing a parent component should be rejected");
        };
        assert!(error.to_string().contains("must not contain `.` or `..`"));
        assert!(!temporary.path().join("repository/.aictx").exists());
    }

    #[test]
    fn concurrent_context_selection_and_removal_preserve_cross_file_invariants() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::for_root(temporary.path().join("aictx"));
        let store = MetadataStore::new(paths.clone());
        store
            .initialize()
            .unwrap_or_else(|error| panic!("initialize: {error}"));

        let profile_id = ProfileId::new(
            Provider::Claude,
            Name::parse("account").unwrap_or_else(|error| panic!("profile name: {error}")),
        );
        let personal =
            Name::parse("personal").unwrap_or_else(|error| panic!("personal context: {error}"));
        let work = Name::parse("work").unwrap_or_else(|error| panic!("work context: {error}"));
        store
            .update_config(|config| {
                config.profiles.insert(
                    profile_id.clone(),
                    Profile::Claude {
                        billing_domain: BillingDomain::AnthropicApi,
                        auth: ClaudeAuth::ApiKey,
                        state_dir: paths.profile_state_dir(Provider::Claude, profile_id.name()),
                        secret_ref: Some("keyring://aictx/test-api-key".to_owned()),
                        account_hint: None,
                        expected_organization: None,
                        wif: None,
                    },
                );
                let context = Context {
                    claude: Some(profile_id.clone()),
                    codex: None,
                };
                config.contexts =
                    BTreeMap::from([(personal.clone(), context.clone()), (work.clone(), context)]);
                config.default_context = Some(personal.clone());
                Ok(())
            })
            .unwrap_or_else(|error| panic!("seed contexts: {error}"));

        let start = Arc::new(Barrier::new(3));
        let selecting_store = store.clone();
        let selecting_start = Arc::clone(&start);
        let selecting_work = work.clone();
        let selecting = thread::spawn(move || {
            selecting_start.wait();
            selecting_store.update_metadata(|config, state| {
                if !config.contexts.contains_key(&selecting_work) {
                    return Err(Error::ContextNotFound(selecting_work.to_string()));
                }
                state.current_context = Some(selecting_work.clone());
                Ok(())
            })
        });

        let removing_store = store.clone();
        let removing_start = Arc::clone(&start);
        let removing_work = work.clone();
        let removing = thread::spawn(move || {
            removing_start.wait();
            removing_store.update_metadata(|config, state| {
                if state.current_context.as_ref() == Some(&removing_work) {
                    return Err(Error::InvalidInput("context is active".to_owned()));
                }
                config.contexts.remove(&removing_work);
                Ok(())
            })
        });

        start.wait();
        let _ = selecting
            .join()
            .unwrap_or_else(|_| panic!("selection thread panicked"));
        let _ = removing
            .join()
            .unwrap_or_else(|_| panic!("removal thread panicked"));

        let (config, state) = store
            .load_metadata()
            .unwrap_or_else(|error| panic!("load consistent metadata: {error}"));
        assert_eq!(
            config.contexts.contains_key(&work),
            state.current_context.as_ref() == Some(&work),
            "a selected context must not be removed from config"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_directory_rejects_a_symlinked_ancestor() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let target = temporary.path().join("target");
        fs::create_dir(&target).unwrap_or_else(|error| panic!("create target: {error}"));
        let linked = temporary.path().join("linked");
        symlink(&target, &linked).unwrap_or_else(|error| panic!("create symlink: {error}"));

        let Err(error) = ensure_secure_directory(&linked.join("sensitive")) else {
            panic!("symlinked ancestor should be rejected");
        };
        assert!(
            error
                .to_string()
                .contains("symlinked security-sensitive path component")
        );
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_file_rejects_a_world_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let unsafe_directory = temporary.path().join("unsafe");
        fs::create_dir(&unsafe_directory)
            .unwrap_or_else(|error| panic!("create unsafe ancestor: {error}"));
        fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o777))
            .unwrap_or_else(|error| panic!("make ancestor writable: {error}"));
        let sensitive = unsafe_directory.join("state.toml");
        fs::write(&sensitive, "version = 1\n")
            .unwrap_or_else(|error| panic!("write sensitive file: {error}"));
        fs::set_permissions(&sensitive, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("secure sensitive file: {error}"));

        let Err(error) = validate_sensitive_file(&sensitive) else {
            panic!("writable ancestor should be rejected");
        };
        assert!(error.to_string().contains("ancestor"));
        assert!(
            error
                .to_string()
                .contains("writable by group or other users")
        );
    }
}
