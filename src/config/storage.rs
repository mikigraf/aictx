use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
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

pub(super) fn acquire_exclusive(path: &Path) -> Result<File> {
    let file = lock_file(path)?;
    file.lock().map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(file)
}

pub(super) fn acquire_shared(path: &Path) -> Result<File> {
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
