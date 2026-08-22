use std::{collections::BTreeMap, path::PathBuf};

use crate::{
    Result,
    config::{
        AppPaths, ProfileLockGuard,
        storage::{ProfileLockAcquisition, try_acquire_profile_lock},
    },
    model::{ProfileId, ProfileUid},
};

pub(super) enum FenceLockAcquisition {
    Acquired(FenceLocks),
    Busy,
}

pub(super) struct FenceLocks {
    pub(super) aliases: RetainedProfileAliases,
    pub(super) lifecycle_path: PathBuf,
    pub(super) lifecycle: ProfileLockGuard,
}

pub(super) struct RetainedProfileAliases {
    pub(super) guards: BTreeMap<ProfileId, ProfileLockGuard>,
}

impl RetainedProfileAliases {
    pub(super) fn contains(&self, profile_ref: &ProfileId) -> bool {
        self.guards.contains_key(profile_ref)
    }
}

pub(super) enum FenceLockSetAcquisition {
    Acquired(BTreeMap<PathBuf, ProfileLockGuard>),
    Busy,
}

pub(super) fn try_acquire_fence_lock_set(
    requests: impl IntoIterator<Item = (PathBuf, bool)>,
) -> Result<FenceLockSetAcquisition> {
    let mut ordered = BTreeMap::new();
    for (path, exclusive) in requests {
        ordered
            .entry(path)
            .and_modify(|current| *current |= exclusive)
            .or_insert(exclusive);
    }
    let mut held = BTreeMap::new();
    for (path, exclusive) in ordered {
        match try_acquire_profile_lock(&path, exclusive)? {
            ProfileLockAcquisition::Acquired(guard) => {
                held.insert(path, guard);
            }
            ProfileLockAcquisition::Busy => return Ok(FenceLockSetAcquisition::Busy),
        }
    }
    Ok(FenceLockSetAcquisition::Acquired(held))
}

pub(super) fn try_acquire_fence_locks(
    paths: &AppPaths,
    profile_refs: impl IntoIterator<Item = ProfileId>,
    profile_uid: &ProfileUid,
    lifecycle_exclusive: bool,
) -> Result<FenceLockAcquisition> {
    let mut aliases_by_path = BTreeMap::new();
    for profile_ref in profile_refs {
        let alias_path = paths.profile_lock(profile_ref.provider(), profile_ref.name());
        if aliases_by_path.insert(alias_path, profile_ref).is_some() {
            return Err(super::unsafe_fence());
        }
    }
    if aliases_by_path.is_empty() {
        return Err(super::unsafe_fence());
    }
    let lifecycle_path = paths.profile_lifecycle_lock(profile_uid);
    let requests = aliases_by_path
        .keys()
        .cloned()
        .map(|path| (path, true))
        .chain(std::iter::once((
            lifecycle_path.clone(),
            lifecycle_exclusive,
        )));
    let held = try_acquire_fence_lock_set(requests)?;
    let FenceLockSetAcquisition::Acquired(mut held) = held else {
        return Ok(FenceLockAcquisition::Busy);
    };
    let mut aliases = BTreeMap::new();
    for (path, profile_ref) in aliases_by_path {
        let Some(guard) = held.remove(&path) else {
            return Err(super::unsafe_fence());
        };
        aliases.insert(profile_ref, guard);
    }
    let Some(lifecycle) = held.remove(&lifecycle_path) else {
        return Err(super::unsafe_fence());
    };
    if !held.is_empty() {
        return Err(super::unsafe_fence());
    }
    Ok(FenceLockAcquisition::Acquired(FenceLocks {
        aliases: RetainedProfileAliases { guards: aliases },
        lifecycle_path,
        lifecycle,
    }))
}
