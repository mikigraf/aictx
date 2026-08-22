#![cfg(unix)]

use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use tempfile::TempDir;

use super::*;
use crate::{
    config::{AppPaths, MetadataStore},
    model::{ProfileUid, Provider},
};

fn fixture() -> (TempDir, PathBuf) {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize: {error}"));
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"));
    let uid = ProfileUid::for_state_dir(
        &config.installation_uid,
        Provider::Claude,
        &paths.profile_state_root(Provider::Claude).join("lock-test"),
    )
    .unwrap_or_else(|error| panic!("profile uid: {error}"));
    let path = paths.profile_lifecycle_lock(&uid);
    (temporary, path)
}

#[test]
fn new_profile_locks_are_private_single_link_and_cloexec() {
    let (_temporary, path) = fixture();
    let guard =
        acquire_profile_lock(&path, true).unwrap_or_else(|error| panic!("acquire lock: {error}"));
    let metadata = fs::metadata(&path).unwrap_or_else(|error| panic!("lock metadata: {error}"));
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    let flags = rustix::io::fcntl_getfd(&guard.file)
        .unwrap_or_else(|error| panic!("lock fd flags: {error}"));
    assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
}

#[test]
fn preexisting_overpermissive_lock_is_refused_without_chmod_or_write() {
    let (_temporary, path) = fixture();
    fs::write(&path, b"preserve me").unwrap_or_else(|error| panic!("write lock: {error}"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|error| panic!("set mode: {error}"));

    assert!(acquire_profile_lock(&path, true).is_err());
    assert_eq!(
        fs::metadata(&path)
            .unwrap_or_else(|error| panic!("lock metadata: {error}"))
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    assert_eq!(
        fs::read(&path).unwrap_or_else(|error| panic!("read lock: {error}")),
        b"preserve me"
    );
}

#[test]
fn symlink_and_hardlink_locks_are_refused_without_mutating_the_target() {
    let (_temporary, path) = fixture();
    let target = path
        .parent()
        .unwrap_or_else(|| panic!("lock path has parent"))
        .join("lock-target");
    fs::write(&target, b"preserve me").unwrap_or_else(|error| panic!("write target: {error}"));
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("set target mode: {error}"));

    symlink(&target, &path).unwrap_or_else(|error| panic!("symlink lock: {error}"));
    assert!(acquire_profile_lock(&path, true).is_err());
    assert_eq!(
        fs::read(&target).unwrap_or_else(|error| panic!("read symlink target: {error}")),
        b"preserve me"
    );
    fs::remove_file(&path).unwrap_or_else(|error| panic!("remove symlink: {error}"));

    fs::hard_link(&target, &path).unwrap_or_else(|error| panic!("hard-link lock: {error}"));
    assert!(acquire_profile_lock(&path, true).is_err());
    assert_eq!(
        fs::read(&target).unwrap_or_else(|error| panic!("read hard-link target: {error}")),
        b"preserve me"
    );
    assert_eq!(
        fs::metadata(&target)
            .unwrap_or_else(|error| panic!("target metadata: {error}"))
            .nlink(),
        2
    );
}

#[test]
fn typed_lock_attempt_distinguishes_contention_from_integrity_errors() {
    let (_temporary, path) = fixture();
    let guard = acquire_profile_lock(&path, true)
        .unwrap_or_else(|error| panic!("acquire first lock: {error}"));
    assert!(matches!(
        try_acquire_profile_lock(&path, true)
            .unwrap_or_else(|error| panic!("contended lock decision: {error}")),
        ProfileLockAcquisition::Busy
    ));
    drop(guard);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|error| panic!("set unsafe mode: {error}"));
    assert!(try_acquire_profile_lock(&path, true).is_err());
}
