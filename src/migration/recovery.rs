use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use super::{
    MigrationPlan, RecoveryOutcome, filesystem,
    journal::{self, JOURNAL_VERSION, JournalPhase, MigrationJournal, PathSignature},
    platform,
};
use crate::{
    Error, Result,
    config::{AppPaths, validate_secure_directory},
};

pub(super) fn recover(legacy: &AppPaths, target: &AppPaths) -> Result<RecoveryOutcome> {
    let _operation_lock = journal::acquire_operation_lock(target)?;
    filesystem::validate_distinct_layouts(legacy, target)?;
    let path = journal::journal_path(target);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RecoveryOutcome::NothingToRecover);
        }
        Err(source) => return Err(Error::ReadFile { path, source }),
    };
    if platform::is_symlink_or_reparse(&metadata) || !metadata.is_file() {
        return Err(Error::PolicyRefused(format!(
            "migration journal {} is not a regular file",
            path.display()
        )));
    }

    let bytes = filesystem::read_sensitive_bytes(&path)?;
    let mut migration: MigrationJournal = filesystem::parse_toml(&path, &bytes)?;
    validate(&migration, legacy, target)?;
    if migration.phase == JournalPhase::Verified {
        let plan =
            MigrationPlan::inspect_source(legacy, target, filesystem::target_anchors(target))?;
        let _profile_locks = plan.acquire_legacy_profile_locks()?;
        let _metadata_lock = filesystem::acquire_legacy_metadata_lock(legacy)?;
        plan.revalidate_source()?;
        journal::verify_committed_target(
            &plan,
            &migration.anchors,
            &migration.transaction_id,
            false,
        )?;
        for anchor in &migration.anchors {
            journal::remove_owner_marker_if_present(&anchor.target, &migration.transaction_id)?;
            remove_owned_tree_if_present(&anchor.stage, &migration.transaction_id)?;
        }
        journal::remove_regular_file(&path)?;
        return Ok(RecoveryOutcome::Finalized);
    }

    let archives = rollback(&mut migration, &path)?;
    Ok(RecoveryOutcome::RolledBack { archives })
}

fn validate(migration: &MigrationJournal, legacy: &AppPaths, target: &AppPaths) -> Result<()> {
    if migration.version != JOURNAL_VERSION
        || !valid_transaction_id(&migration.transaction_id)
        || migration.legacy != PathSignature::from(legacy)
        || migration.target != PathSignature::from(target)
    {
        return Err(Error::PolicyRefused(
            "migration journal does not match the requested legacy and target paths".to_owned(),
        ));
    }
    let expected_targets = filesystem::target_anchors(target);
    if migration.anchors.len() != expected_targets.len() {
        return Err(Error::PolicyRefused(
            "migration journal contains an unexpected target layout".to_owned(),
        ));
    }
    for (index, (anchor, expected)) in migration
        .anchors
        .iter()
        .zip(expected_targets.iter())
        .enumerate()
    {
        if &anchor.target != expected
            || anchor.stage != journal::stage_path(expected, &migration.transaction_id, index)
            || anchor.archive.as_ref().is_some_and(|archive| {
                !valid_archive_path(expected, archive, &migration.transaction_id, index)
            })
        {
            return Err(Error::PolicyRefused(
                "migration journal contains an unexpected staging or archive path".to_owned(),
            ));
        }
    }
    Ok(())
}

fn valid_archive_path(
    target: &Path,
    archive: &Path,
    transaction_id: &str,
    anchor_index: usize,
) -> bool {
    let Some(name) = target.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let Some(archive_name) = archive.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let prefix = format!(".{name}.ctxlane-migration-rollback-{transaction_id}-{anchor_index}-");
    archive.parent() == target.parent()
        && archive_name.strip_prefix(&prefix).is_some_and(|counter| {
            !counter.is_empty() && counter.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn valid_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

pub(super) fn rollback(migration: &mut MigrationJournal, path: &Path) -> Result<Vec<PathBuf>> {
    let mut archives = Vec::new();
    for index in 0..migration.anchors.len() {
        let target_exists = match fs::symlink_metadata(&migration.anchors[index].target) {
            Ok(metadata) => {
                if platform::is_symlink_or_reparse(&metadata) {
                    return Err(unexpected_tree_object(&migration.anchors[index].target));
                }
                true
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(Error::ReadFile {
                    path: migration.anchors[index].target.clone(),
                    source,
                });
            }
        };
        if target_exists && migration.anchors[index].archive.is_none() {
            validate_secure_directory(&migration.anchors[index].target)?;
            journal::validate_owner_marker(
                &migration.anchors[index].target,
                &migration.transaction_id,
            )?;
            validate_removable_tree(&migration.anchors[index].target)?;
            let archive = choose_archive_path(
                &migration.anchors[index].target,
                &migration.transaction_id,
                index,
            )?;
            migration.anchors[index].archive = Some(archive);
            journal::write(path, migration)?;
        }

        if !target_exists
            && migration.anchors[index].committed
            && migration.anchors[index].archive.is_none()
        {
            return Err(Error::PolicyRefused(format!(
                "committed migration target is missing and has no archive: {}",
                migration.anchors[index].target.display()
            )));
        }

        if let Some(archive) = migration.anchors[index].archive.clone() {
            archive_committed_target(
                &migration.anchors[index].target,
                &archive,
                &migration.transaction_id,
            )?;
            archives.push(archive);
        }
        remove_owned_tree_if_present(&migration.anchors[index].stage, &migration.transaction_id)?;
    }
    remove_regular_file_if_present(path)?;
    Ok(archives)
}

fn choose_archive_path(
    target: &Path,
    transaction_id: &str,
    anchor_index: usize,
) -> Result<PathBuf> {
    let name = target
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("ctxlane");
    for collision_index in 0..10_000_u32 {
        let candidate = target.with_file_name(format!(
            ".{name}.ctxlane-migration-rollback-{transaction_id}-{anchor_index}-{collision_index}"
        ));
        match fs::symlink_metadata(&candidate) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {}
            Err(source) => {
                return Err(Error::ReadFile {
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(Error::PolicyRefused(format!(
        "could not allocate a collision-safe migration archive beside {}",
        target.display()
    )))
}

fn archive_committed_target(target: &Path, archive: &Path, transaction_id: &str) -> Result<()> {
    let target_metadata = fs::symlink_metadata(target);
    let archive_metadata = fs::symlink_metadata(archive);
    match (target_metadata, archive_metadata) {
        (Ok(metadata), Err(source)) if source.kind() == std::io::ErrorKind::NotFound => {
            if platform::is_symlink_or_reparse(&metadata) {
                return Err(unexpected_tree_object(target));
            }
            validate_secure_directory(target)?;
            journal::validate_owner_marker(target, transaction_id)?;
            validate_removable_tree(target)?;
            fs::rename(target, archive).map_err(|source| Error::WriteFile {
                path: archive.to_path_buf(),
                source,
            })?;
            filesystem::sync_parent(archive)?;
            journal::validate_owner_marker(archive, transaction_id)
        }
        (Err(source), Ok(metadata)) if source.kind() == std::io::ErrorKind::NotFound => {
            if platform::is_symlink_or_reparse(&metadata) {
                return Err(unexpected_tree_object(archive));
            }
            validate_secure_directory(archive)?;
            journal::validate_owner_marker(archive, transaction_id)?;
            validate_removable_tree(archive)
        }
        (Ok(_), Ok(_)) => Err(Error::PolicyRefused(format!(
            "migration target and planned archive both exist: {} and {}",
            target.display(),
            archive.display()
        ))),
        (Err(target_error), Err(archive_error))
            if target_error.kind() == std::io::ErrorKind::NotFound
                && archive_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Err(Error::PolicyRefused(format!(
                "migration-owned target and planned archive are both missing: {}",
                target.display()
            )))
        }
        (Err(source), _) => Err(Error::ReadFile {
            path: target.to_path_buf(),
            source,
        }),
        (_, Err(source)) => Err(Error::ReadFile {
            path: archive.to_path_buf(),
            source,
        }),
    }
}

fn remove_owned_tree_if_present(path: &Path, transaction_id: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if platform::is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
                return Err(unexpected_tree_object(path));
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(Error::ReadFile {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    journal::validate_owner_marker(path, transaction_id)?;
    validate_removable_tree(path)?;
    fs::remove_dir_all(path).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    filesystem::sync_parent(path)
}

fn validate_removable_tree(path: &Path) -> Result<()> {
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
        if platform::is_symlink_or_reparse(&metadata) || (!metadata.is_dir() && !metadata.is_file())
        {
            return Err(unexpected_tree_object(&child));
        }
        if metadata.is_dir() {
            validate_removable_tree(&child)?;
        }
    }
    Ok(())
}

fn unexpected_tree_object(path: &Path) -> Error {
    Error::PolicyRefused(format!(
        "refusing migration tree containing an unexpected object: {}",
        path.display()
    ))
}

fn remove_regular_file_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if platform::is_symlink_or_reparse(&metadata) || !metadata.is_file() {
                return Err(Error::PolicyRefused(format!(
                    "refusing to remove unexpected file object {}",
                    path.display()
                )));
            }
            journal::remove_regular_file(path)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}
