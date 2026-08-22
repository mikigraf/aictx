use std::{
    fs::File,
    path::{Path, PathBuf},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::{fs, io::Write};

use crate::{
    Error, Result,
    model::{InstallationUid, ProfileId, ProfileUid},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::orphan_fence;
use super::unsafe_fence;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use super::unsupported;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::config::validate_secure_directory;

const FENCE_FORMAT: &str = "ctxlane-profile-automation-fence";
const FENCE_VERSION: u8 = 1;
const FENCE_ID_PREFIX: &str = "fence_";
const MAX_FENCE_BYTES: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MarkerSnapshot {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    owner: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

pub(super) struct FenceBinding {
    pub(super) installation_uid: InstallationUid,
    pub(super) profile_ref: ProfileId,
    pub(super) profile_uid: ProfileUid,
    pub(super) fence_id: String,
    pub(super) marker_bytes: Vec<u8>,
    pub(super) marker_snapshot: MarkerSnapshot,
    pub(super) marker: File,
    pub(super) marker_path: PathBuf,
    pub(super) lifecycle_path: PathBuf,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) struct OpenedMarker {
    pub(super) file: File,
    pub(super) profile_ref: ProfileId,
    pub(super) fence_id: String,
    pub(super) bytes: Vec<u8>,
    pub(super) snapshot: MarkerSnapshot,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) enum NewMarkerFailure {
    Outer(Error),
    CleanupDeferred(Error),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
enum MarkerCreationFailure {
    BeforeCreate(Error),
    AfterCreate(Error),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn marker_presence(path: &Path) -> Result<bool> {
    let parent = path.parent().ok_or_else(unsafe_fence)?;
    validate_secure_directory(parent)?;
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(metadata) => {
            validate_open_marker_metadata(path, &metadata)?;
            Ok(true)
        }
        Err(_) => Err(unsafe_fence()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
// This zero-filesystem stub intentionally preserves the supported Result API.
#[allow(clippy::unnecessary_wraps)]
pub(super) fn marker_presence(path: &Path) -> Result<bool> {
    let _ = path;
    Ok(false)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn create_new_marker(
    path: &Path,
    installation_uid: &InstallationUid,
    profile_ref: &ProfileId,
    profile_uid: &ProfileUid,
) -> std::result::Result<OpenedMarker, NewMarkerFailure> {
    let parent = marker_parent(path).map_err(NewMarkerFailure::Outer)?;
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(NewMarkerFailure::CleanupDeferred(orphan_fence())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(NewMarkerFailure::Outer(unsafe_fence())),
    }
    let fence_id = generate_fence_id().map_err(NewMarkerFailure::Outer)?;
    let expected_bytes = encode_marker(installation_uid, profile_ref, profile_uid, &fence_id);
    match create_marker(&parent, path, &expected_bytes) {
        Ok(()) => {}
        Err(MarkerCreationFailure::BeforeCreate(Error::WriteFile { source, .. }))
            if source.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            return Err(NewMarkerFailure::CleanupDeferred(orphan_fence()));
        }
        Err(MarkerCreationFailure::BeforeCreate(error)) => {
            return Err(NewMarkerFailure::Outer(error));
        }
        Err(MarkerCreationFailure::AfterCreate(error)) => {
            return Err(NewMarkerFailure::CleanupDeferred(error));
        }
    }
    let opened = open_existing_marker(path, installation_uid, Some(profile_ref), profile_uid)
        .map_err(NewMarkerFailure::CleanupDeferred)?;
    if opened.fence_id != fence_id || opened.bytes != expected_bytes {
        return Err(NewMarkerFailure::CleanupDeferred(unsafe_fence()));
    }
    Ok(opened)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_marker(
    parent: &File,
    path: &Path,
    bytes: &[u8],
) -> std::result::Result<(), MarkerCreationFailure> {
    use std::os::unix::fs::PermissionsExt;

    let leaf = path
        .file_name()
        .ok_or_else(|| MarkerCreationFailure::BeforeCreate(unsafe_fence()))?;
    let owned = rustix::fs::openat(
        parent,
        Path::new(leaf),
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .map_err(|source| {
        MarkerCreationFailure::BeforeCreate(Error::WriteFile {
            path: path.to_path_buf(),
            source: source.into(),
        })
    })?;
    let mut file = File::from(owned);
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| {
            MarkerCreationFailure::AfterCreate(Error::WriteFile {
                path: path.to_path_buf(),
                source,
            })
        })?;
    let metadata = file.metadata().map_err(|source| {
        MarkerCreationFailure::AfterCreate(Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })
    })?;
    validate_open_marker_metadata(path, &metadata).map_err(MarkerCreationFailure::AfterCreate)?;
    file.write_all(bytes).map_err(|source| {
        MarkerCreationFailure::AfterCreate(Error::WriteFile {
            path: path.to_path_buf(),
            source,
        })
    })?;
    file.sync_all().map_err(|source| {
        MarkerCreationFailure::AfterCreate(Error::WriteFile {
            path: path.to_path_buf(),
            source,
        })
    })?;
    parent.sync_all().map_err(|source| {
        MarkerCreationFailure::AfterCreate(Error::WriteFile {
            path: path
                .parent()
                .map_or_else(|| path.to_path_buf(), Path::to_path_buf),
            source,
        })
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn open_existing_marker(
    path: &Path,
    installation_uid: &InstallationUid,
    profile_ref: Option<&ProfileId>,
    profile_uid: &ProfileUid,
) -> Result<OpenedMarker> {
    let parent = marker_parent(path)?;
    let current = fs::symlink_metadata(path).map_err(|_| unsafe_fence())?;
    validate_open_marker_metadata(path, &current)?;
    let leaf = path.file_name().ok_or_else(unsafe_fence)?;
    let owned = rustix::fs::openat(
        &parent,
        Path::new(leaf),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| unsafe_fence())?;
    let marker = File::from(owned);
    let validated =
        read_and_validate_marker(&marker, path, installation_uid, profile_ref, profile_uid)?;
    Ok(OpenedMarker {
        file: marker,
        profile_ref: validated.profile_ref,
        fence_id: validated.fence_id,
        bytes: validated.bytes,
        snapshot: validated.snapshot,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn marker_parent(path: &Path) -> Result<File> {
    use std::os::unix::fs::MetadataExt;

    let parent = path.parent().ok_or_else(unsafe_fence)?;
    validate_secure_directory(parent)?;
    let directory = File::from(
        rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| unsafe_fence())?,
    );
    let opened = directory.metadata().map_err(|_| unsafe_fence())?;
    let current = fs::symlink_metadata(parent).map_err(|_| unsafe_fence())?;
    if !opened.is_dir() || opened.dev() != current.dev() || opened.ino() != current.ino() {
        return Err(unsafe_fence());
    }
    Ok(directory)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ValidatedMarker {
    profile_ref: ProfileId,
    fence_id: String,
    bytes: Vec<u8>,
    snapshot: MarkerSnapshot,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_and_validate_marker(
    marker: &File,
    path: &Path,
    installation_uid: &InstallationUid,
    profile_ref: Option<&ProfileId>,
    profile_uid: &ProfileUid,
) -> Result<ValidatedMarker> {
    use std::os::unix::fs::FileExt;

    let before = marker.metadata().map_err(|_| unsafe_fence())?;
    validate_open_marker_metadata(path, &before)?;
    if before.len() > MAX_FENCE_BYTES {
        return Err(unsafe_fence());
    }
    let expected_len = usize::try_from(before.len()).map_err(|_| unsafe_fence())?;
    let mut bytes = vec![0_u8; expected_len.saturating_add(1)];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let read = marker
            .read_at(
                &mut bytes[offset..],
                u64::try_from(offset).map_err(|_| unsafe_fence())?,
            )
            .map_err(|_| unsafe_fence())?;
        if read == 0 {
            break;
        }
        offset = offset.checked_add(read).ok_or_else(unsafe_fence)?;
    }
    bytes.truncate(offset);
    if bytes.len() != expected_len {
        return Err(unsafe_fence());
    }
    let after = marker.metadata().map_err(|_| unsafe_fence())?;
    if marker_snapshot(&before) != marker_snapshot(&after) {
        return Err(unsafe_fence());
    }
    let (profile_ref, fence_id) = parse_marker(&bytes, installation_uid, profile_ref, profile_uid)?;
    validate_path_matches_open_marker(path, &after)?;
    Ok(ValidatedMarker {
        profile_ref,
        fence_id,
        bytes,
        snapshot: marker_snapshot(&after),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn validate_marker(binding: &FenceBinding) -> Result<()> {
    let validated = read_and_validate_marker(
        &binding.marker,
        &binding.marker_path,
        &binding.installation_uid,
        Some(&binding.profile_ref),
        &binding.profile_uid,
    )?;
    if validated.fence_id != binding.fence_id
        || validated.bytes != binding.marker_bytes
        || validated.snapshot != binding.marker_snapshot
    {
        return Err(unsafe_fence());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn validate_marker(binding: &FenceBinding) -> Result<()> {
    let _ = binding;
    Err(unsupported())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_open_marker_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_FENCE_BYTES
    {
        return Err(Error::PolicyRefused(format!(
            "automation profile fence is unsafe ({})",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn marker_snapshot(metadata: &fs::Metadata) -> MarkerSnapshot {
    use std::os::unix::fs::MetadataExt;

    MarkerSnapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_path_matches_open_marker(path: &Path, opened: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let current = fs::symlink_metadata(path).map_err(|_| unsafe_fence())?;
    if current.dev() != opened.dev()
        || current.ino() != opened.ino()
        || current.nlink() != 1
        || marker_snapshot(opened) != marker_snapshot(&current)
    {
        return Err(unsafe_fence());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn unlink_exact_marker(binding: &FenceBinding) -> Result<()> {
    let parent = marker_parent(&binding.marker_path)?;
    let leaf = binding.marker_path.file_name().ok_or_else(unsafe_fence)?;
    let opened = binding.marker.metadata().map_err(|_| unsafe_fence())?;
    let current = fs::symlink_metadata(&binding.marker_path).map_err(|_| unsafe_fence())?;
    if marker_snapshot(&opened) != binding.marker_snapshot
        || marker_snapshot(&current) != binding.marker_snapshot
    {
        return Err(unsafe_fence());
    }
    rustix::fs::unlinkat(&parent, Path::new(leaf), rustix::fs::AtFlags::empty()).map_err(|source| {
        Error::WriteFile {
            path: binding.marker_path.clone(),
            source: source.into(),
        }
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn unlink_exact_marker(binding: &FenceBinding) -> Result<()> {
    let _ = binding;
    Err(unsupported())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn sync_marker_parent(path: &Path) -> Result<()> {
    let parent_path = path.parent().ok_or_else(unsafe_fence)?;
    marker_parent(path)?
        .sync_all()
        .map_err(|source| Error::WriteFile {
            path: parent_path.to_path_buf(),
            source,
        })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn sync_marker_parent(path: &Path) -> Result<()> {
    let _ = path;
    Err(unsupported())
}

pub(super) fn encode_marker(
    installation_uid: &InstallationUid,
    profile_ref: &ProfileId,
    profile_uid: &ProfileUid,
    fence_id: &str,
) -> Vec<u8> {
    format!(
        "format = \"{FENCE_FORMAT}\"\nversion = {FENCE_VERSION}\ninstallation_uid = \"{installation_uid}\"\nprofile_ref = \"{profile_ref}\"\nprofile_uid = \"{profile_uid}\"\nfence_id = \"{fence_id}\"\n"
    )
    .into_bytes()
}

fn parse_marker(
    bytes: &[u8],
    installation_uid: &InstallationUid,
    expected_profile_ref: Option<&ProfileId>,
    profile_uid: &ProfileUid,
) -> Result<(ProfileId, String)> {
    let text = std::str::from_utf8(bytes).map_err(|_| unsafe_fence())?;
    let prefix = format!(
        "format = \"{FENCE_FORMAT}\"\nversion = {FENCE_VERSION}\ninstallation_uid = \"{installation_uid}\"\nprofile_ref = \""
    );
    let (raw_profile_ref, tail) = text
        .strip_prefix(&prefix)
        .and_then(|value| value.split_once("\"\nprofile_uid = \""))
        .ok_or_else(unsafe_fence)?;
    let profile_ref = raw_profile_ref
        .parse::<ProfileId>()
        .map_err(|_| unsafe_fence())?;
    if expected_profile_ref.is_some_and(|expected| expected != &profile_ref) {
        return Err(unsafe_fence());
    }
    let fence_prefix = format!("{profile_uid}\"\nfence_id = \"");
    let fence_id = tail
        .strip_prefix(&fence_prefix)
        .and_then(|value| value.strip_suffix("\"\n"))
        .filter(|value| valid_fence_id(value))
        .ok_or_else(unsafe_fence)?;
    if encode_marker(installation_uid, &profile_ref, profile_uid, fence_id) != bytes {
        return Err(unsafe_fence());
    }
    Ok((profile_ref, fence_id.to_owned()))
}

fn valid_fence_id(value: &str) -> bool {
    value.len() == FENCE_ID_PREFIX.len() + 32
        && value.starts_with(FENCE_ID_PREFIX)
        && value[FENCE_ID_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn generate_fence_id() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| {
        Error::PolicyRefused(
            "operating-system randomness is unavailable for automation profile fencing".to_owned(),
        )
    })?;
    let mut encoded = String::with_capacity(FENCE_ID_PREFIX.len() + 32);
    encoded.push_str(FENCE_ID_PREFIX);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_| unsafe_fence())?;
    }
    Ok(encoded)
}
