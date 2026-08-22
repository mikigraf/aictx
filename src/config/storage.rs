use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use serde::Serialize;

use super::{
    LeafOwnership, validate_absolute_sensitive_path, validate_sensitive_file,
    validate_trusted_path_chain,
};
use crate::{Error, Result};

pub(super) fn write_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
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
    for _ in 0..2 {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                validate_sensitive_file(path)?;
                let file = open_existing_lock(path).map_err(|source| Error::ReadFile {
                    path: path.to_path_buf(),
                    source,
                })?;
                validate_opened_lock(path, &file)?;
                return Ok(file);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                match create_lock(path) {
                    Ok(file) => {
                        validate_opened_lock(path, &file)?;
                        return Ok(file);
                    }
                    Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(source) => {
                        return Err(Error::WriteFile {
                            path: path.to_path_buf(),
                            source,
                        });
                    }
                }
            }
            Err(source) => {
                return Err(Error::ReadFile {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    Err(Error::PolicyRefused(format!(
        "security-sensitive lock changed while it was opened ({})",
        path.display()
    )))
}

#[cfg(unix)]
fn open_existing_lock(path: &Path) -> std::io::Result<File> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(Into::into)
}

#[cfg(not(unix))]
fn open_existing_lock(path: &Path) -> std::io::Result<File> {
    fs::OpenOptions::new().read(true).write(true).open(path)
}

#[cfg(unix)]
fn create_lock(path: &Path) -> std::io::Result<File> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .map(File::from)
    .map_err(Into::into)
}

#[cfg(not(unix))]
fn create_lock(path: &Path) -> std::io::Result<File> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

fn validate_opened_lock(path: &Path, file: &File) -> Result<()> {
    let opened = file.metadata().map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if !opened.is_file() {
        return Err(Error::PolicyRefused(format!(
            "{} is not a regular lock file",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if opened.uid() != rustix::process::getuid().as_raw()
            || opened.permissions().mode() & 0o077 != 0
            || opened.nlink() != 1
        {
            return Err(Error::PolicyRefused(format!(
                "{} is not an owner-private single-link lock file",
                path.display()
            )));
        }
        let current = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        if current.dev() != opened.dev() || current.ino() != opened.ino() {
            return Err(Error::PolicyRefused(format!(
                "security-sensitive lock changed while it was opened ({})",
                path.display()
            )));
        }
    }

    validate_sensitive_file(path)
}

pub(super) fn acquire_exclusive(path: &Path) -> Result<File> {
    let file = lock_file(path)?;
    file.lock().map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    validate_opened_lock(path, &file)?;
    Ok(file)
}

pub(super) fn acquire_shared(path: &Path) -> Result<File> {
    let file = lock_file(path)?;
    file.lock_shared().map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    validate_opened_lock(path, &file)?;
    Ok(file)
}

pub(crate) struct ProfileLockGuard {
    file: File,
}

pub(super) enum ProfileLockConversion {
    Converted(ProfileLockGuard),
    // flock conversion may discard the prior mode before WouldBlock. The FD
    // remains retained, but callers must not treat it as shared or exclusive.
    Busy(ProfileLockGuard),
    // Non-contention failure also retains the FD without promising its mode.
    Failed(ProfileLockGuard, Error),
}

pub(super) enum ProfileLockAcquisition {
    Acquired(ProfileLockGuard),
    Busy,
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
impl ProfileLockGuard {
    pub(super) fn downgrade_to_shared(self, path: &Path) -> ProfileLockConversion {
        match self.file.try_lock_shared() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return ProfileLockConversion::Busy(self),
            Err(fs::TryLockError::Error(source)) => {
                return ProfileLockConversion::Failed(
                    self,
                    Error::ReadFile {
                        path: path.to_path_buf(),
                        source,
                    },
                );
            }
        }
        if let Err(error) = validate_opened_lock(path, &self.file) {
            return ProfileLockConversion::Failed(self, error);
        }
        ProfileLockConversion::Converted(self)
    }

    pub(super) fn try_upgrade_to_exclusive(self, path: &Path) -> ProfileLockConversion {
        match self.file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return ProfileLockConversion::Busy(self),
            Err(fs::TryLockError::Error(source)) => {
                return ProfileLockConversion::Failed(
                    self,
                    Error::ReadFile {
                        path: path.to_path_buf(),
                        source,
                    },
                );
            }
        }
        if let Err(error) = validate_opened_lock(path, &self.file) {
            return ProfileLockConversion::Failed(self, error);
        }
        ProfileLockConversion::Converted(self)
    }
}

pub(crate) struct OrderedProfileLocks {
    locks: Vec<(PathBuf, ProfileLockGuard)>,
}

impl OrderedProfileLocks {
    pub(crate) fn guard(&self, path: &Path) -> Result<&ProfileLockGuard> {
        self.locks
            .iter()
            .find_map(|(locked_path, guard)| (locked_path == path).then_some(guard))
            .ok_or(Error::ConfigBusy)
    }
}

pub(crate) fn acquire_profile_lock(path: &Path, exclusive: bool) -> Result<ProfileLockGuard> {
    match try_acquire_profile_lock(path, exclusive)? {
        ProfileLockAcquisition::Acquired(guard) => Ok(guard),
        ProfileLockAcquisition::Busy => Err(Error::PolicyRefused(format!(
            "profile is busy (lock file {})",
            path.display()
        ))),
    }
}

pub(super) fn try_acquire_profile_lock(
    path: &Path,
    exclusive: bool,
) -> Result<ProfileLockAcquisition> {
    let file = lock_file(path)?;
    let result = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    match result {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            return Ok(ProfileLockAcquisition::Busy);
        }
        Err(fs::TryLockError::Error(source)) => {
            return Err(Error::ReadFile {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    validate_opened_lock(path, &file)?;
    Ok(ProfileLockAcquisition::Acquired(ProfileLockGuard { file }))
}

pub(crate) fn acquire_ordered_profile_locks(
    requests: impl IntoIterator<Item = (PathBuf, bool)>,
) -> Result<OrderedProfileLocks> {
    let mut ordered = BTreeMap::new();
    for (path, exclusive) in requests {
        ordered
            .entry(path)
            .and_modify(|current| *current |= exclusive)
            .or_insert(exclusive);
    }
    let locks = ordered
        .into_iter()
        .map(|(path, exclusive)| acquire_profile_lock(&path, exclusive).map(|guard| (path, guard)))
        .collect::<Result<Vec<_>>>()?;
    Ok(OrderedProfileLocks { locks })
}

#[cfg(test)]
mod tests;
