use std::{
    ffi::OsStr,
    fs::{self, File},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::{
    MigrationPlan, MigrationReceipt, filesystem, platform, recovery, validate_managed_metadata,
};
use crate::{
    Error, Result,
    config::{AppPaths, ensure_secure_directory, write_secure_text},
    model::{Config, MutableState},
};

pub(super) const JOURNAL_VERSION: u32 = 1;
pub(super) const OWNER_MARKER: &str = ".ctxlane-migration-owner";
const STAGE_FRAGMENT: &str = ".ctxlane-migration-stage-";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationJournal {
    pub(super) version: u32,
    pub(super) transaction_id: String,
    pub(super) legacy: PathSignature,
    pub(super) target: PathSignature,
    pub(super) phase: JournalPhase,
    pub(super) anchors: Vec<JournalAnchor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PathSignature {
    config: PathBuf,
    data: PathBuf,
    state: PathBuf,
}

impl From<&AppPaths> for PathSignature {
    fn from(paths: &AppPaths) -> Self {
        Self {
            config: paths.config_dir.clone(),
            data: paths.data_dir.clone(),
            state: paths.state_dir.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum JournalPhase {
    Staging,
    Staged,
    Committing,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JournalAnchor {
    pub(super) target: PathBuf,
    pub(super) stage: PathBuf,
    pub(super) committed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) archive: Option<PathBuf>,
}

pub(super) fn journal_path(target: &AppPaths) -> PathBuf {
    let config_name = target
        .config_dir
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("ctxlane");
    target
        .config_dir
        .parent()
        .unwrap_or(&target.config_dir)
        .join(format!(".{config_name}.aictx-to-ctxlane-migration.toml"))
}

pub(super) fn operation_lock_path(target: &AppPaths) -> PathBuf {
    let explicit_root = [
        (target.config_dir.as_path(), "config"),
        (target.data_dir.as_path(), "data"),
        (target.state_dir.as_path(), "state"),
    ]
    .iter()
    .all(|(path, name)| path.file_name().is_some_and(|value| value == *name))
        && target.config_dir.parent() == target.data_dir.parent()
        && target.config_dir.parent() == target.state_dir.parent();
    let layout_hash = layout_hash(target);
    if explicit_root {
        let parent = target
            .config_dir
            .parent()
            .and_then(Path::parent)
            .or_else(|| target.config_dir.parent())
            .unwrap_or(&target.config_dir);
        return parent
            .join(format!(".ctxlane-migration-locks-{layout_hash:016x}"))
            .join("operation.lock");
    }

    target
        .config_dir
        .parent()
        .unwrap_or(&target.config_dir)
        .join(format!(
            ".ctxlane-migration-operation-{layout_hash:016x}.lock"
        ))
}

fn layout_hash(paths: &AppPaths) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for path in [&paths.config_dir, &paths.data_dir, &paths.state_dir] {
        for byte in path.to_string_lossy().bytes().chain(std::iter::once(0xff)) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

pub(super) fn acquire_operation_lock(target: &AppPaths) -> Result<File> {
    filesystem::acquire_operation_lock(&operation_lock_path(target), true)
}

pub(super) fn acquire_startup_lock(target: &AppPaths) -> Result<File> {
    filesystem::acquire_operation_lock(&operation_lock_path(target), false)
}

pub(super) fn ensure_no_journal(target: &AppPaths) -> Result<()> {
    let journal = journal_path(target);
    match fs::symlink_metadata(&journal) {
        Ok(metadata) if platform::is_symlink_or_reparse(&metadata) || !metadata.is_file() => {
            Err(Error::PolicyRefused(format!(
                "unexpected migration journal object at {}",
                journal.display()
            )))
        }
        Ok(_) => Err(Error::PolicyRefused(format!(
            "an incomplete migration journal exists at {}; run `ctxlane migrate recover` with the same `--root` and `--from-root` path selection used for migration",
            journal.display()
        ))),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::ReadFile {
            path: journal,
            source,
        }),
    }
}

pub(super) fn execute(plan: &MigrationPlan) -> Result<MigrationReceipt> {
    let transaction_id = transaction_id()?;
    let path = journal_path(&plan.target);
    let (mut journal, created_parents) = prepare(plan, &transaction_id, &path)?;

    match execute_transaction(plan, &mut journal, &path) {
        Ok(receipt) => Ok(receipt),
        Err(error) => match recovery::rollback(&mut journal, &path) {
            Ok(archives) => {
                filesystem::remove_created_parents(&created_parents);
                if archives.is_empty() {
                    Err(error)
                } else {
                    let archive_paths = archives
                        .iter()
                        .map(|archive| archive.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    Err(Error::PolicyRefused(format!(
                        "migration failed ({error}); committed partial target state was archived for review at {archive_paths}"
                    )))
                }
            }
            Err(cleanup_error) => Err(Error::PolicyRefused(format!(
                "migration failed ({error}); cleanup also failed ({cleanup_error}); recover the journal at {} before retrying",
                path.display()
            ))),
        },
    }
}

fn prepare(
    plan: &MigrationPlan,
    transaction_id: &str,
    path: &Path,
) -> Result<(MigrationJournal, Vec<PathBuf>)> {
    let mut created_parents = Vec::new();
    let result = (|| {
        let mut parents = plan
            .anchors
            .iter()
            .filter_map(|anchor| anchor.parent().map(Path::to_path_buf))
            .collect::<Vec<_>>();
        if let Some(parent) = path.parent() {
            parents.push(parent.to_path_buf());
        }
        parents.sort();
        parents.dedup();
        for parent in parents {
            let missing = filesystem::missing_directories(&parent)?;
            created_parents.extend(missing.iter().cloned());
            filesystem::ensure_trusted_parent(&parent, &missing)?;
        }

        filesystem::validate_target_is_absent(&plan.anchors)?;
        ensure_no_journal(&plan.target)?;
        let anchors = plan
            .anchors
            .iter()
            .enumerate()
            .map(|(index, target)| JournalAnchor {
                target: target.clone(),
                stage: stage_path(target, transaction_id, index),
                committed: false,
                archive: None,
            })
            .collect::<Vec<_>>();
        for anchor in &anchors {
            filesystem::ensure_path_absent(&anchor.stage, "migration staging directory")?;
        }

        let journal = MigrationJournal {
            version: JOURNAL_VERSION,
            transaction_id: transaction_id.to_owned(),
            legacy: PathSignature::from(&plan.legacy),
            target: PathSignature::from(&plan.target),
            phase: JournalPhase::Staging,
            anchors,
        };
        let text = toml::to_string_pretty(&journal)?;
        filesystem::write_secure_new(path, format!("{text}\n").as_bytes())?;
        Ok(journal)
    })();

    match result {
        Ok(journal) => Ok((journal, created_parents)),
        Err(error) => {
            filesystem::remove_created_parents(&created_parents);
            Err(error)
        }
    }
}

fn execute_transaction(
    plan: &MigrationPlan,
    journal: &mut MigrationJournal,
    path: &Path,
) -> Result<MigrationReceipt> {
    for anchor in &journal.anchors {
        filesystem::create_secure_directory_new(&anchor.stage)?;
        filesystem::write_secure_new(
            &anchor.stage.join(OWNER_MARKER),
            format!("{}\n", journal.transaction_id).as_bytes(),
        )?;
    }

    for directory in filesystem::target_layout_directories(&plan.target) {
        ensure_secure_directory(&map_target_to_stage(&directory, &journal.anchors)?)?;
    }

    let config_text = toml::to_string_pretty(&plan.migrated_config)?;
    let state_text = toml::to_string_pretty(&plan.state)?;
    filesystem::write_secure_new(
        &map_target_to_stage(&plan.target.config_file, &journal.anchors)?,
        format!("{config_text}\n").as_bytes(),
    )?;
    filesystem::write_secure_new(
        &map_target_to_stage(&plan.target.state_file, &journal.anchors)?,
        format!("{state_text}\n").as_bytes(),
    )?;

    let legacy_vendor_root = plan.legacy.data_dir.join("vendor-state");
    let target_vendor_root = plan.target.data_dir.join("vendor-state");
    for entry in &plan.vendor_entries {
        let source = legacy_vendor_root.join(&entry.relative);
        let target = target_vendor_root.join(&entry.relative);
        let staged = map_target_to_stage(&target, &journal.anchors)?;
        match entry.kind {
            filesystem::VendorEntryKind::Directory => {
                filesystem::create_secure_directory_new(&staged)?;
            }
            filesystem::VendorEntryKind::File(expected) => {
                filesystem::copy_regular_file(&source, &staged, expected)?;
            }
        }
    }
    for anchor in &journal.anchors {
        filesystem::sync_tree(&anchor.stage)?;
    }

    plan.revalidate_source()?;
    journal.phase = JournalPhase::Staged;
    write(path, journal)?;
    filesystem::validate_target_is_absent(&plan.anchors)?;

    for index in commit_order(&journal.anchors, &plan.target.config_file) {
        let anchor = &mut journal.anchors[index];
        fs::rename(&anchor.stage, &anchor.target).map_err(|source| Error::WriteFile {
            path: anchor.target.clone(),
            source,
        })?;
        filesystem::sync_parent(&anchor.target)?;
        anchor.committed = true;
        journal.phase = JournalPhase::Committing;
        write(path, journal)?;
    }

    verify_committed_target(plan, &journal.anchors, &journal.transaction_id, true)?;
    journal.phase = JournalPhase::Verified;
    write(path, journal)?;
    for anchor in &journal.anchors {
        remove_owner_marker_if_present(&anchor.target, &journal.transaction_id)?;
    }
    remove_regular_file(path)?;

    Ok(MigrationReceipt {
        summary: plan.summary.clone(),
        config_file: plan.target.config_file.clone(),
        state_file: plan.target.state_file.clone(),
    })
}

pub(super) fn verify_committed_target(
    plan: &MigrationPlan,
    anchors: &[JournalAnchor],
    transaction_id: &str,
    require_markers: bool,
) -> Result<()> {
    let config_bytes = filesystem::read_sensitive_bytes(&plan.target.config_file)?;
    let state_bytes = filesystem::read_sensitive_bytes(&plan.target.state_file)?;
    let expected_config = format!("{}\n", toml::to_string_pretty(&plan.migrated_config)?);
    let expected_state = format!("{}\n", toml::to_string_pretty(&plan.state)?);
    if config_bytes != expected_config.as_bytes() || state_bytes != expected_state.as_bytes() {
        return Err(Error::InvalidConfig(
            "committed migration metadata bytes do not match the staged plan".to_owned(),
        ));
    }
    let config: Config = filesystem::parse_toml(&plan.target.config_file, &config_bytes)?;
    let state: MutableState = filesystem::parse_toml(&plan.target.state_file, &state_bytes)?;
    if config != plan.migrated_config || state != plan.state {
        return Err(Error::InvalidConfig(
            "committed migration metadata does not match the staged plan".to_owned(),
        ));
    }
    validate_managed_metadata(&config, &state, &plan.target, "migrated")?;
    filesystem::verify_vendor_copy(
        &plan.vendor_entries,
        &plan.legacy.data_dir.join("vendor-state"),
        &plan.target.data_dir.join("vendor-state"),
    )?;
    let mut marker_paths = Vec::new();
    for anchor in anchors {
        let marker = anchor.target.join(OWNER_MARKER);
        match fs::symlink_metadata(&marker) {
            Ok(_) => {
                validate_owner_marker(&anchor.target, transaction_id)?;
                marker_paths.push(marker);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound && !require_markers => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::InvalidConfig(format!(
                    "migration ownership marker is missing from {}",
                    anchor.target.display()
                )));
            }
            Err(source) => {
                return Err(Error::ReadFile {
                    path: marker,
                    source,
                });
            }
        }
    }
    filesystem::verify_exact_target_layout(
        &plan.target,
        &plan.vendor_entries,
        &anchors
            .iter()
            .map(|anchor| anchor.target.clone())
            .collect::<Vec<_>>(),
        &marker_paths,
    )?;
    Ok(())
}

pub(super) fn validate_owner_marker(path: &Path, transaction_id: &str) -> Result<()> {
    let actual = read_marker(&path.join(OWNER_MARKER))?;
    if actual != transaction_id {
        return Err(Error::PolicyRefused(format!(
            "migration ownership marker does not match at {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_marker(path: &Path) -> Result<String> {
    let bytes = filesystem::read_sensitive_bytes(path)?;
    String::from_utf8(bytes)
        .map(|value| value.trim_end().to_owned())
        .map_err(|_| Error::InvalidConfig(format!("invalid migration marker {}", path.display())))
}

pub(super) fn remove_owner_marker_if_present(path: &Path, transaction_id: &str) -> Result<()> {
    let marker = path.join(OWNER_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => {
            validate_owner_marker(path, transaction_id)?;
            remove_regular_file(&marker)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::ReadFile {
            path: marker,
            source,
        }),
    }
}

pub(super) fn write(path: &Path, journal: &MigrationJournal) -> Result<()> {
    let text = toml::to_string_pretty(journal)?;
    write_secure_text(path, &format!("{text}\n"))?;
    filesystem::sync_parent(path)
}

fn map_target_to_stage(target: &Path, anchors: &[JournalAnchor]) -> Result<PathBuf> {
    for anchor in anchors {
        if let Ok(relative) = target.strip_prefix(&anchor.target) {
            return Ok(anchor.stage.join(relative));
        }
    }
    Err(Error::InvalidConfig(format!(
        "migration target {} is outside the staged application layout",
        target.display()
    )))
}

fn commit_order(anchors: &[JournalAnchor], config_file: &Path) -> Vec<usize> {
    let mut order = (0..anchors.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| {
        let contains_config = config_file.starts_with(&anchors[*index].target);
        (contains_config, anchors[*index].target.clone())
    });
    order
}

pub(super) fn stage_path(target: &Path, transaction_id: &str, index: usize) -> PathBuf {
    let name = target
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("ctxlane");
    target.with_file_name(format!(".{name}{STAGE_FRAGMENT}{transaction_id}-{index}"))
}

fn transaction_id() -> Result<String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::InvalidConfig(format!("system clock is invalid: {error}")))?;
    Ok(format!("{:x}-{:x}", std::process::id(), elapsed.as_nanos()))
}

pub(super) fn remove_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if platform::is_symlink_or_reparse(&metadata) || !metadata.is_file() {
        return Err(Error::PolicyRefused(format!(
            "refusing to remove non-regular migration file {}",
            path.display()
        )));
    }
    fs::remove_file(path).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    filesystem::sync_parent(path)
}
