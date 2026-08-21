use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::de::DeserializeOwned;

use super::platform::{is_symlink_or_reparse, reject_reparse_points_in_existing_chain};
use crate::{
    Error, Result,
    config::{
        AppPaths, LeafOwnership, validate_secure_directory, validate_sensitive_file,
        validate_trusted_path_chain,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileFingerprint {
    pub(super) length: u64,
    modified: Option<SystemTime>,
    owner_executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VendorEntryKind {
    Directory,
    File(FileFingerprint),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VendorEntry {
    pub(super) relative: PathBuf,
    pub(super) kind: VendorEntryKind,
}

pub(super) fn acquire_legacy_metadata_lock(paths: &AppPaths) -> Result<File> {
    let lock_path = paths.state_dir.join("metadata.lock");
    validate_existing_regular_object(&lock_path, "legacy metadata lock")?;
    validate_sensitive_file(&lock_path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|source| Error::ReadFile {
            path: lock_path.clone(),
            source,
        })?;
    file.try_lock().map_err(|_| Error::ConfigBusy)?;
    Ok(file)
}

pub(super) fn acquire_operation_lock(path: &Path, exclusive: bool) -> Result<File> {
    let parent = path.parent().ok_or_else(|| {
        Error::InvalidConfig(format!(
            "migration operation lock has no parent: {}",
            path.display()
        ))
    })?;
    reject_reparse_points_in_existing_chain(parent)?;
    let missing = missing_directories(parent)?;
    ensure_trusted_parent(parent, &missing)?;

    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if is_symlink_or_reparse(&metadata) || !metadata.is_file() {
                return Err(Error::PolicyRefused(format!(
                    "migration operation lock {} is not a regular file",
                    path.display()
                )));
            }
            validate_sensitive_file(path)?;
            true
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(Error::ReadFile {
                path: path.to_path_buf(),
                source,
            });
        }
    };
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
    validate_sensitive_file(path)?;
    if !existed {
        sync_parent(path)?;
    }
    let lock_result = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    lock_result.map_err(|_| Error::ConfigBusy)?;
    Ok(file)
}

pub(super) fn vendor_manifest(root: &Path) -> Result<(Vec<VendorEntry>, Vec<PathBuf>)> {
    let metadata = fs::symlink_metadata(root).map_err(|source| Error::ReadFile {
        path: root.to_path_buf(),
        source,
    })?;
    if is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(Error::PolicyRefused(format!(
            "legacy vendor-state root is not a regular directory: {}",
            root.display()
        )));
    }
    validate_secure_directory(root)?;
    let mut entries = Vec::new();
    let mut skipped_locks = Vec::new();
    inspect_vendor_tree(root, Path::new(""), &mut entries, &mut skipped_locks)?;
    Ok((entries, skipped_locks))
}

fn inspect_vendor_tree(
    root: &Path,
    relative: &Path,
    entries: &mut Vec<VendorEntry>,
    skipped_locks: &mut Vec<PathBuf>,
) -> Result<()> {
    let directory = root.join(relative);
    let read_dir = fs::read_dir(&directory).map_err(|source| Error::ReadFile {
        path: directory.clone(),
        source,
    })?;
    let mut children = read_dir
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|source| Error::ReadFile {
            path: directory.clone(),
            source,
        })?;
    children.sort_by_key(fs::DirEntry::file_name);

    for child in children {
        let name = child.file_name();
        let child_relative = relative.join(&name);
        let path = child.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| Error::ReadFile {
            path: path.clone(),
            source,
        })?;
        if is_symlink_or_reparse(&metadata) {
            return Err(Error::PolicyRefused(format!(
                "refusing symlink or Windows reparse point in legacy vendor state: {}",
                path.display()
            )));
        }
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(Error::PolicyRefused(format!(
                "refusing special file in legacy vendor state: {}",
                path.display()
            )));
        }
        if metadata.is_file() && is_runtime_lock_name(&name) {
            skipped_locks.push(child_relative);
            continue;
        }
        if metadata.is_dir() {
            entries.push(VendorEntry {
                relative: child_relative.clone(),
                kind: VendorEntryKind::Directory,
            });
            inspect_vendor_tree(root, &child_relative, entries, skipped_locks)?;
        } else if metadata.is_file() {
            entries.push(VendorEntry {
                relative: child_relative,
                kind: VendorEntryKind::File(file_fingerprint(&metadata)),
            });
        }
    }
    Ok(())
}

fn file_fingerprint(metadata: &fs::Metadata) -> FileFingerprint {
    FileFingerprint {
        length: metadata.len(),
        modified: metadata.modified().ok(),
        owner_executable: owner_executable(metadata),
    }
}

fn is_runtime_lock_name(name: &OsStr) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|extension| extension == "lock")
}

#[cfg(unix)]
fn owner_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
const fn owner_executable(_metadata: &fs::Metadata) -> bool {
    false
}

pub(super) fn copy_regular_file(
    source: &Path,
    target: &Path,
    expected: FileFingerprint,
) -> Result<()> {
    let before = fs::symlink_metadata(source).map_err(|source_error| Error::ReadFile {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if is_symlink_or_reparse(&before) || !before.is_file() || file_fingerprint(&before) != expected
    {
        return Err(Error::ConfigBusy);
    }

    let mut input = File::open(source).map_err(|source_error| Error::ReadFile {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    let mut output = secure_create_new_options()
        .open(target)
        .map_err(|source_error| Error::WriteFile {
            path: target.to_path_buf(),
            source: source_error,
        })?;
    std::io::copy(&mut input, &mut output).map_err(|source_error| Error::WriteFile {
        path: target.to_path_buf(),
        source: source_error,
    })?;
    output.sync_all().map_err(|source_error| Error::WriteFile {
        path: target.to_path_buf(),
        source: source_error,
    })?;
    set_safe_copied_permissions(target, expected.owner_executable)?;
    output.sync_all().map_err(|source_error| Error::WriteFile {
        path: target.to_path_buf(),
        source: source_error,
    })?;
    sync_parent(target)?;

    let after = input.metadata().map_err(|source_error| Error::ReadFile {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if file_fingerprint(&after) != expected {
        return Err(Error::ConfigBusy);
    }
    Ok(())
}

#[cfg(unix)]
fn set_safe_copied_permissions(path: &Path, owner_executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if owner_executable { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn set_safe_copied_permissions(path: &Path, _owner_executable: bool) -> Result<()> {
    validate_existing_regular_object(path, "copied vendor-state entry")
}

pub(super) fn target_anchors(paths: &AppPaths) -> Vec<PathBuf> {
    let mut candidates = vec![
        paths.config_dir.clone(),
        paths.data_dir.clone(),
        paths.state_dir.clone(),
    ];
    candidates.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    candidates.dedup();

    let mut anchors = Vec::<PathBuf>::new();
    for candidate in candidates {
        if !anchors.iter().any(|anchor| candidate.starts_with(anchor)) {
            anchors.push(candidate);
        }
    }
    anchors.sort();
    anchors
}

pub(super) fn target_layout_directories(paths: &AppPaths) -> Vec<PathBuf> {
    let mut directories = vec![
        paths.config_dir.clone(),
        paths.data_dir.clone(),
        paths.state_dir.clone(),
        paths.data_dir.join("vendor-state"),
        paths.state_dir.join("profile-locks"),
    ];
    directories.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    directories.dedup();
    directories
}

pub(super) fn validate_distinct_layouts(legacy: &AppPaths, target: &AppPaths) -> Result<()> {
    let legacy_dirs = [&legacy.config_dir, &legacy.data_dir, &legacy.state_dir];
    let target_dirs = [&target.config_dir, &target.data_dir, &target.state_dir];
    for path in legacy_dirs.iter().chain(target_dirs.iter()) {
        reject_reparse_points_in_existing_chain(path)?;
    }
    for legacy_dir in legacy_dirs {
        for target_dir in target_dirs {
            if legacy_dir.starts_with(target_dir) || target_dir.starts_with(legacy_dir) {
                return Err(Error::PolicyRefused(format!(
                    "legacy and target migration directories must not overlap: {} and {}",
                    legacy_dir.display(),
                    target_dir.display()
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_target_is_absent(anchors: &[PathBuf]) -> Result<()> {
    for anchor in anchors {
        ensure_path_absent(anchor, "target application directory")?;
    }
    Ok(())
}

pub(super) fn validate_target_parents(anchors: &[PathBuf], journal_path: &Path) -> Result<()> {
    for path in anchors
        .iter()
        .filter_map(|anchor| anchor.parent())
        .chain(journal_path.parent())
    {
        validate_trusted_path_chain(path, LeafOwnership::CurrentUser)?;
    }
    Ok(())
}

pub(super) fn ensure_path_absent(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let kind = if is_symlink_or_reparse(&metadata) {
                "symlink or Windows reparse point"
            } else if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else {
                "special file"
            };
            Err(Error::PolicyRefused(format!(
                "{label} {} already exists as a {kind}; migration never overwrites a target",
                path.display()
            )))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(super) fn verify_vendor_copy(
    expected: &[VendorEntry],
    legacy_root: &Path,
    target_root: &Path,
) -> Result<()> {
    let (actual, skipped) = vendor_manifest(target_root)?;
    if !vendor_contents_match(expected, &actual) || !skipped.is_empty() {
        return Err(Error::InvalidConfig(
            "committed vendor state does not match the staged migration plan".to_owned(),
        ));
    }
    for entry in expected {
        if matches!(entry.kind, VendorEntryKind::File(_))
            && !regular_files_equal(
                &legacy_root.join(&entry.relative),
                &target_root.join(&entry.relative),
            )?
        {
            return Err(Error::InvalidConfig(format!(
                "copied vendor-state file does not match its legacy source: {}",
                entry.relative.display()
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayoutKind {
    Directory,
    File,
}

pub(super) fn verify_exact_target_layout(
    paths: &AppPaths,
    vendor_entries: &[VendorEntry],
    anchors: &[PathBuf],
    marker_paths: &[PathBuf],
) -> Result<()> {
    let mut expected = BTreeMap::new();
    for directory in target_layout_directories(paths) {
        insert_layout_entry(&mut expected, &directory, LayoutKind::Directory)?;
    }
    insert_layout_entry(&mut expected, &paths.config_file, LayoutKind::File)?;
    insert_layout_entry(&mut expected, &paths.state_file, LayoutKind::File)?;
    let vendor_root = paths.data_dir.join("vendor-state");
    for entry in vendor_entries {
        let kind = match entry.kind {
            VendorEntryKind::Directory => LayoutKind::Directory,
            VendorEntryKind::File(_) => LayoutKind::File,
        };
        insert_layout_entry(&mut expected, &vendor_root.join(&entry.relative), kind)?;
    }
    for marker in marker_paths {
        insert_layout_entry(&mut expected, marker, LayoutKind::File)?;
    }

    let mut actual = BTreeMap::new();
    for anchor in anchors {
        inspect_target_layout(anchor, &mut actual)?;
    }
    if expected != actual {
        let mismatch = expected
            .keys()
            .chain(actual.keys())
            .find(|path| expected.get(*path) != actual.get(*path));
        return Err(Error::InvalidConfig(format!(
            "committed migration layout differs from the staged plan{}",
            mismatch.map_or_else(String::new, |path| format!(": {}", path.display()))
        )));
    }
    Ok(())
}

fn insert_layout_entry(
    entries: &mut BTreeMap<PathBuf, LayoutKind>,
    path: &Path,
    kind: LayoutKind,
) -> Result<()> {
    if let Some(previous) = entries.insert(path.to_path_buf(), kind)
        && previous != kind
    {
        return Err(Error::InvalidConfig(format!(
            "migration layout path has conflicting types: {}",
            path.display()
        )));
    }
    Ok(())
}

fn inspect_target_layout(path: &Path, entries: &mut BTreeMap<PathBuf, LayoutKind>) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if is_symlink_or_reparse(&metadata) {
        return Err(Error::PolicyRefused(format!(
            "refusing symlink or Windows reparse point in migrated target: {}",
            path.display()
        )));
    }
    let kind = if metadata.is_dir() {
        validate_secure_directory(path)?;
        LayoutKind::Directory
    } else if metadata.is_file() {
        validate_sensitive_file(path)?;
        LayoutKind::File
    } else {
        return Err(Error::PolicyRefused(format!(
            "refusing special file in migrated target: {}",
            path.display()
        )));
    };
    insert_layout_entry(entries, path, kind)?;
    if kind == LayoutKind::Directory {
        for entry in fs::read_dir(path).map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })? {
            let entry = entry.map_err(|source| Error::ReadFile {
                path: path.to_path_buf(),
                source,
            })?;
            inspect_target_layout(&entry.path(), entries)?;
        }
    }
    Ok(())
}

fn vendor_contents_match(expected: &[VendorEntry], actual: &[VendorEntry]) -> bool {
    expected.len() == actual.len()
        && expected.iter().zip(actual).all(|(left, right)| {
            left.relative == right.relative
                && match (left.kind, right.kind) {
                    (VendorEntryKind::Directory, VendorEntryKind::Directory) => true,
                    (VendorEntryKind::File(left), VendorEntryKind::File(right)) => {
                        left.length == right.length
                            && left.owner_executable == right.owner_executable
                    }
                    (VendorEntryKind::Directory | VendorEntryKind::File(_), _) => false,
                }
        })
}

fn regular_files_equal(left: &Path, right: &Path) -> Result<bool> {
    const BUFFER_SIZE: usize = 64 * 1024;
    let mut left_file = File::open(left).map_err(|source| Error::ReadFile {
        path: left.to_path_buf(),
        source,
    })?;
    let mut right_file = File::open(right).map_err(|source| Error::ReadFile {
        path: right.to_path_buf(),
        source,
    })?;
    let mut left_buffer = vec![0_u8; BUFFER_SIZE].into_boxed_slice();
    let mut right_buffer = vec![0_u8; BUFFER_SIZE].into_boxed_slice();
    loop {
        let left_count =
            std::io::Read::read(&mut left_file, &mut left_buffer).map_err(|source| {
                Error::ReadFile {
                    path: left.to_path_buf(),
                    source,
                }
            })?;
        let right_count =
            std::io::Read::read(&mut right_file, &mut right_buffer).map_err(|source| {
                Error::ReadFile {
                    path: right.to_path_buf(),
                    source,
                }
            })?;
        if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count] {
            return Ok(false);
        }
        if left_count == 0 {
            return Ok(true);
        }
    }
}

pub(super) fn read_sensitive_bytes(path: &Path) -> Result<Vec<u8>> {
    validate_existing_regular_object(path, "migration metadata")?;
    validate_sensitive_file(path)?;
    fs::read(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_existing_regular_object(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if is_symlink_or_reparse(&metadata) || !metadata.is_file() {
        return Err(Error::PolicyRefused(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn read_optional_sensitive_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_sensitive_bytes(path).map(Some),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(super) fn parse_toml<T: DeserializeOwned>(path: &Path, bytes: &[u8]) -> Result<T> {
    let text = std::str::from_utf8(bytes).map_err(|_| redacted_parse_error(path))?;
    toml::from_str(text).map_err(|_| redacted_parse_error(path))
}

fn redacted_parse_error(path: &Path) -> Error {
    Error::InvalidConfig(format!(
        "failed to parse TOML metadata in {}; parser details and input were redacted",
        path.display()
    ))
}

pub(super) fn write_secure_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = secure_create_new_options()
        .open(path)
        .map_err(|source| Error::WriteFile {
            path: path.to_path_buf(),
            source,
        })?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(Error::WriteFile {
            path: path.to_path_buf(),
            source,
        });
    }
    validate_sensitive_file(path)?;
    sync_parent(path)
}

fn secure_create_new_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

pub(super) fn create_secure_directory_new(path: &Path) -> Result<()> {
    validate_trusted_path_chain(path, LeafOwnership::CurrentUser)?;
    #[cfg(unix)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|source| Error::CreateDir {
        path: path.to_path_buf(),
        source,
    })?;
    validate_secure_directory(path)?;
    sync_parent(path)
}

pub(super) fn missing_directories(path: &Path) -> Result<Vec<PathBuf>> {
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
    Ok(missing)
}

pub(super) fn ensure_trusted_parent(path: &Path, missing: &[PathBuf]) -> Result<()> {
    reject_reparse_points_in_existing_chain(path)?;
    validate_trusted_path_chain(path, LeafOwnership::CurrentUser)?;
    for directory in missing.iter().rev() {
        match create_secure_directory_new(directory) {
            Ok(()) => {}
            Err(Error::CreateDir { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                // Another valid ctxlane process may win the first-use directory race.
                // Continue only after treating the new object as fully untrusted and
                // revalidating its type, ownership, permissions, and path chain.
                reject_reparse_points_in_existing_chain(directory)?;
                validate_secure_directory(directory)?;
                sync_parent(directory)?;
            }
            Err(error) => return Err(error),
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(Error::PolicyRefused(format!(
            "migration parent {} is not a trusted directory",
            path.display()
        )));
    }
    validate_trusted_path_chain(path, LeafOwnership::CurrentUser)
}

pub(super) fn remove_created_parents(paths: &[PathBuf]) {
    let mut unique = paths
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    unique.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in unique {
        let _ = fs::remove_dir(path);
    }
}

pub(super) fn sync_tree(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() || is_symlink_or_reparse(&metadata) {
        return Err(Error::PolicyRefused(format!(
            "cannot sync non-directory migration tree {}",
            path.display()
        )));
    }
    for entry in fs::read_dir(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child).map_err(|source| Error::ReadFile {
            path: child.clone(),
            source,
        })?;
        if is_symlink_or_reparse(&metadata) || (!metadata.is_dir() && !metadata.is_file()) {
            return Err(Error::PolicyRefused(format!(
                "cannot sync migration tree containing an unexpected object: {}",
                child.display()
            )));
        }
        if metadata.is_dir() {
            sync_tree(&child)?;
        }
    }
    sync_directory(path)
}

pub(super) fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    let directory = File::open(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    directory.sync_all().map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn sync_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(Error::PolicyRefused(format!(
            "cannot validate non-directory migration parent {}",
            path.display()
        )));
    }
    Ok(())
}
