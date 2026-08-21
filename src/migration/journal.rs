use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::{
    MigrationPlan, MigrationReceipt, RecoveryOutcome, filesystem, validate_managed_metadata,
};
use crate::{
    Error, Result,
    config::{AppPaths, ensure_secure_directory, write_secure_text},
    model::{Config, MutableState},
};

const JOURNAL_VERSION: u32 = 1;
const OWNER_MARKER: &str = ".ctxlane-migration-owner";
const STAGE_FRAGMENT: &str = ".ctxlane-migration-stage-";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationJournal {
    version: u32,
    transaction_id: String,
    legacy: PathSignature,
    target: PathSignature,
    phase: JournalPhase,
    anchors: Vec<JournalAnchor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PathSignature {
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
enum JournalPhase {
    Staging,
    Staged,
    Committing,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalAnchor {
    target: PathBuf,
    stage: PathBuf,
    committed: bool,
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

pub(super) fn ensure_no_journal(target: &AppPaths) -> Result<()> {
    let journal = journal_path(target);
    match fs::symlink_metadata(&journal) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::PolicyRefused(format!(
                "unexpected migration journal object at {}",
                journal.display()
            )))
        }
        Ok(_) => Err(Error::PolicyRefused(format!(
            "an incomplete migration journal exists at {}; recover it before retrying",
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
        Err(error) => match rollback(&journal, &path) {
            Ok(()) => {
                filesystem::remove_created_parents(&created_parents);
                Err(error)
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
        anchor.committed = true;
        journal.phase = JournalPhase::Committing;
        write(path, journal)?;
    }

    verify_committed_target(plan, &journal.anchors, &journal.transaction_id)?;
    journal.phase = JournalPhase::Verified;
    write(path, journal)?;
    for anchor in &journal.anchors {
        remove_owner_marker_if_present(&anchor.target, &journal.transaction_id)?;
    }
    remove_regular_file(path)?;

    Ok(MigrationReceipt {
        summary: plan.summary,
        config_file: plan.target.config_file.clone(),
        state_file: plan.target.state_file.clone(),
    })
}

fn verify_committed_target(
    plan: &MigrationPlan,
    anchors: &[JournalAnchor],
    transaction_id: &str,
) -> Result<()> {
    let config_bytes = filesystem::read_sensitive_bytes(&plan.target.config_file)?;
    let state_bytes = filesystem::read_sensitive_bytes(&plan.target.state_file)?;
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
    for anchor in anchors {
        validate_owner_marker(&anchor.target, transaction_id)?;
    }
    Ok(())
}

pub(super) fn recover(legacy: &AppPaths, target: &AppPaths) -> Result<RecoveryOutcome> {
    let path = journal_path(target);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RecoveryOutcome::NothingToRecover);
        }
        Err(source) => {
            return Err(Error::ReadFile { path, source });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::PolicyRefused(format!(
            "migration journal {} is not a regular file",
            path.display()
        )));
    }

    let bytes = filesystem::read_sensitive_bytes(&path)?;
    let journal: MigrationJournal = filesystem::parse_toml(&path, &bytes)?;
    validate(&journal, legacy, target)?;
    if journal.phase == JournalPhase::Verified {
        validate_committed_metadata(target)?;
        for anchor in &journal.anchors {
            remove_owner_marker_if_present(&anchor.target, &journal.transaction_id)?;
            remove_owned_tree_if_present(&anchor.stage, &journal.transaction_id)?;
        }
        remove_regular_file(&path)?;
        return Ok(RecoveryOutcome::Finalized);
    }

    rollback(&journal, &path)?;
    Ok(RecoveryOutcome::RolledBack)
}

fn validate_committed_metadata(target: &AppPaths) -> Result<()> {
    let config_bytes = filesystem::read_sensitive_bytes(&target.config_file)?;
    let state_bytes = filesystem::read_sensitive_bytes(&target.state_file)?;
    let config: Config = filesystem::parse_toml(&target.config_file, &config_bytes)?;
    let state: MutableState = filesystem::parse_toml(&target.state_file, &state_bytes)?;
    validate_managed_metadata(&config, &state, target, "migrated")
}

fn validate(journal: &MigrationJournal, legacy: &AppPaths, target: &AppPaths) -> Result<()> {
    if journal.version != JOURNAL_VERSION
        || !valid_transaction_id(&journal.transaction_id)
        || journal.legacy != PathSignature::from(legacy)
        || journal.target != PathSignature::from(target)
    {
        return Err(Error::PolicyRefused(
            "migration journal does not match the requested legacy and target paths".to_owned(),
        ));
    }
    let expected_targets = filesystem::target_anchors(target);
    if journal.anchors.len() != expected_targets.len() {
        return Err(Error::PolicyRefused(
            "migration journal contains an unexpected target layout".to_owned(),
        ));
    }
    for (index, (anchor, expected)) in journal
        .anchors
        .iter()
        .zip(expected_targets.iter())
        .enumerate()
    {
        if &anchor.target != expected
            || anchor.stage != stage_path(expected, &journal.transaction_id, index)
        {
            return Err(Error::PolicyRefused(
                "migration journal contains an unexpected staging path".to_owned(),
            ));
        }
    }
    Ok(())
}

fn valid_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn rollback(journal: &MigrationJournal, path: &Path) -> Result<()> {
    for anchor in &journal.anchors {
        remove_owned_tree_if_present(&anchor.target, &journal.transaction_id)?;
        remove_owned_tree_if_present(&anchor.stage, &journal.transaction_id)?;
    }
    remove_regular_file_if_present(path)
}

fn remove_owned_tree_if_present(path: &Path, transaction_id: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Error::PolicyRefused(format!(
                    "refusing to remove unexpected migration artifact {}",
                    path.display()
                )));
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
    validate_owner_marker(path, transaction_id)?;
    validate_removable_tree(path)?;
    fs::remove_dir_all(path).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
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
        if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
            return Err(Error::PolicyRefused(format!(
                "refusing to remove migration tree containing an unexpected object: {}",
                child.display()
            )));
        }
        if metadata.is_dir() {
            validate_removable_tree(&child)?;
        }
    }
    Ok(())
}

fn validate_owner_marker(path: &Path, transaction_id: &str) -> Result<()> {
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

fn remove_owner_marker_if_present(path: &Path, transaction_id: &str) -> Result<()> {
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

fn write(path: &Path, journal: &MigrationJournal) -> Result<()> {
    let text = toml::to_string_pretty(journal)?;
    write_secure_text(path, &format!("{text}\n"))
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

fn stage_path(target: &Path, transaction_id: &str, index: usize) -> PathBuf {
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

fn remove_regular_file_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::PolicyRefused(format!(
                    "refusing to remove unexpected file object {}",
                    path.display()
                )));
            }
            remove_regular_file(path)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::PolicyRefused(format!(
            "refusing to remove non-regular migration file {}",
            path.display()
        )));
    }
    fs::remove_file(path).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}
