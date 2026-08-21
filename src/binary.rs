use std::{
    env,
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::{
    Error, Result,
    config::{LeafOwnership, validate_trusted_path_chain},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalProgram {
    Claude,
    Codex,
}

impl ExternalProgram {
    const fn label(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BinaryOverrides {
    pub claude: Option<PathBuf>,
    pub codex: Option<PathBuf>,
}

static BINARY_OVERRIDES: OnceLock<BinaryOverrides> = OnceLock::new();

pub fn set_binary_overrides(overrides: BinaryOverrides) -> Result<()> {
    BINARY_OVERRIDES.set(overrides).map_err(|_| {
        Error::InvalidInput("process binary overrides were initialized more than once".to_owned())
    })
}

/// Resolve an external executable without trusting a repository-local PATH entry.
///
/// Every resolved path is rejected when it points into the current Git
/// worktree, including explicit overrides and absolute configured paths.
pub fn resolve_external_binary(configured: &Path, program: ExternalProgram) -> Result<PathBuf> {
    let explicit_override = BINARY_OVERRIDES.get().and_then(|overrides| match program {
        ExternalProgram::Claude => overrides.claude.as_ref(),
        ExternalProgram::Codex => overrides.codex.as_ref(),
    });
    let requested = explicit_override.map_or_else(|| configured.to_path_buf(), PathBuf::clone);
    if explicit_override.is_some() && !requested.is_absolute() {
        return Err(Error::InvalidInput(format!(
            "{} override must be an absolute path: {}",
            program.label(),
            requested.display()
        )));
    }
    let label = program.label();
    let resolved = which::which(&requested).map_err(|error| {
        Error::VendorIncompatible(format!(
            "could not resolve {label} executable `{}`: {error}",
            requested.display()
        ))
    })?;
    let canonical = resolved.canonicalize().map_err(|source| Error::ReadFile {
        path: resolved,
        source,
    })?;
    #[cfg(windows)]
    validate_windows_native_executable(&canonical, label)?;
    validate_trusted_path_chain(&canonical, LeafOwnership::CurrentUserOrRoot)?;

    if let Ok(current) = env::current_exe().and_then(|path| path.canonicalize())
        && current == canonical
    {
        return Err(Error::VendorIncompatible(format!(
            "resolved {label} executable points back to ctxlane ({})",
            canonical.display()
        )));
    }
    if is_in_current_repository(&canonical) {
        return Err(Error::VendorIncompatible(format!(
            "refusing {label} executable inside the current Git worktree ({}); configure a trusted path outside the repository",
            canonical.display()
        )));
    }

    let metadata = canonical.metadata().map_err(|source| Error::ReadFile {
        path: canonical.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(Error::VendorIncompatible(format!(
            "{} is not a regular executable file",
            canonical.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(Error::VendorIncompatible(format!(
                "{} is not executable",
                canonical.display()
            )));
        }
        if mode & 0o022 != 0 {
            return Err(Error::PolicyRefused(format!(
                "external executable {} is writable by group or other users",
                canonical.display()
            )));
        }
    }

    Ok(canonical)
}

#[cfg(windows)]
fn validate_windows_native_executable(path: &Path, label: &str) -> Result<()> {
    let is_command_script = path.extension().is_some_and(|extension| {
        let extension = extension.to_string_lossy();
        extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
    });
    if is_command_script {
        return Err(Error::VendorIncompatible(format!(
            "refusing {label} command script {} because Windows executes .bat/.cmd through cmd.exe; configure a native .exe",
            path.display()
        )));
    }
    Ok(())
}

#[must_use]
pub fn is_in_current_repository(candidate: &Path) -> bool {
    let Ok(cwd) = env::current_dir().and_then(|path| path.canonicalize()) else {
        return false;
    };
    let Some(root) = cwd
        .ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
    else {
        return false;
    };
    canonicalize_with_missing(candidate).is_ok_and(|candidate| candidate.starts_with(root))
}

/// Remove search-path entries that could select a repository-local or
/// replaceable interpreter for an otherwise trusted vendor script.
pub(crate) fn sanitize_search_path(value: &OsStr) -> Result<Option<OsString>> {
    let mut trusted = Vec::new();
    for entry in env::split_paths(value) {
        if !entry.is_absolute() {
            continue;
        }
        let Ok(canonical) = entry.canonicalize() else {
            continue;
        };
        if is_in_current_repository(&canonical) {
            continue;
        }
        let Ok(metadata) = canonical.metadata() else {
            continue;
        };
        if !metadata.is_dir()
            || validate_trusted_path_chain(&canonical, LeafOwnership::CurrentUserOrRoot).is_err()
        {
            continue;
        }
        // Preserve the path that was actually inspected. Retaining `entry`
        // here would reintroduce a symlink-swap window between validation and
        // the child interpreter's PATH lookup.
        if !trusted.contains(&canonical) {
            trusted.push(canonical);
        }
    }
    if trusted.is_empty() {
        return Ok(None);
    }
    env::join_paths(trusted).map(Some).map_err(|error| {
        Error::InvalidConfig(format!("could not construct a trusted child PATH: {error}"))
    })
}

fn canonicalize_with_missing(path: &Path) -> io::Result<PathBuf> {
    let mut cursor = path;
    let mut missing = Vec::<OsString>::new();
    loop {
        match cursor.canonicalize() {
            Ok(mut canonical) => {
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = cursor.file_name().ok_or(error)?;
                missing.push(name.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "path has no existing ancestor")
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn executable_under_a_world_writable_ancestor_is_refused() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let unsafe_directory = temporary.path().join("unsafe-bin");
        fs::create_dir(&unsafe_directory)
            .unwrap_or_else(|error| panic!("create unsafe executable directory: {error}"));
        fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o777))
            .unwrap_or_else(|error| panic!("make executable directory writable: {error}"));
        let executable = unsafe_directory.join("claude");
        fs::write(&executable, "#!/bin/sh\nexit 0\n")
            .unwrap_or_else(|error| panic!("write fake executable: {error}"));
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("make fake executable executable: {error}"));

        let Err(error) = resolve_external_binary(&executable, ExternalProgram::Claude) else {
            panic!("writable executable ancestor should be rejected");
        };
        assert!(error.to_string().contains("ancestor"));
        assert!(
            error
                .to_string()
                .contains("writable by group or other users")
        );
    }

    #[test]
    fn sanitized_path_emits_the_canonical_directory() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let trusted = temporary.path().join("trusted-bin");
        fs::create_dir(&trusted)
            .unwrap_or_else(|error| panic!("create trusted directory: {error}"));
        fs::set_permissions(&trusted, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("secure trusted directory: {error}"));
        let alias = temporary.path().join("bin-alias");
        symlink(&trusted, &alias).unwrap_or_else(|error| panic!("create path alias: {error}"));

        let sanitized = sanitize_search_path(alias.as_os_str())
            .unwrap_or_else(|error| panic!("sanitize PATH: {error}"))
            .unwrap_or_else(|| panic!("trusted path should be retained"));
        let entries = env::split_paths(&sanitized).collect::<Vec<_>>();
        let canonical = trusted
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonicalize trusted directory: {error}"));
        assert_eq!(entries, vec![canonical]);
        assert_ne!(entries, vec![alias]);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn command_scripts_are_not_accepted_as_native_vendor_executables() {
        let path = Path::new(r"C:\tools\codex.cmd");
        let Err(error) = validate_windows_native_executable(path, "vendor") else {
            panic!("Windows command script should be rejected");
        };
        assert!(error.to_string().contains("configure a native .exe"));
        assert!(
            validate_windows_native_executable(Path::new(r"C:\tools\codex.exe"), "codex").is_ok()
        );
    }
}
