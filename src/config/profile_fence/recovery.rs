use std::collections::BTreeMap;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::{fs, path::PathBuf};

use crate::{
    Error, Result,
    config::{AppPaths, MetadataStore},
    model::{InstallationUid, ProfileUid},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::model::ProfileId;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::current_profile_ref_for_uid;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use super::unsupported;
use super::{ProfileAutomationFenceGuard, unsafe_fence};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::{
    locks::{FenceLockSetAcquisition, RetainedProfileAliases, try_acquire_fence_lock_set},
    marker::{FenceBinding, OpenedMarker, open_existing_marker, validate_marker},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
const FENCE_SUFFIX: &str = "-automation.fence";

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct InspectedFence {
    profile_uid: ProfileUid,
    marker_path: PathBuf,
    alias_refs: Vec<ProfileId>,
    current_profile_ref: Option<ProfileId>,
    lifecycle_path: PathBuf,
    marker: OpenedMarker,
}

pub(crate) fn recover_profile_automation_fences(
    paths: &AppPaths,
    installation_uid: &InstallationUid,
) -> Result<BTreeMap<ProfileUid, ProfileAutomationFenceGuard>> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (paths, installation_uid);
        Err(unsupported())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;

        let directory = paths.state_dir.join("profile-locks");
        crate::config::validate_secure_directory(&directory)?;
        let mut profile_uids = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|source| Error::ReadFile {
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| Error::ReadFile {
                path: directory.clone(),
                source,
            })?;
            let file_name = entry.file_name();
            if !file_name.as_bytes().ends_with(FENCE_SUFFIX.as_bytes()) {
                continue;
            }
            let name = file_name.to_str().ok_or_else(|| {
                Error::PolicyRefused(
                    "automation profile fence directory contains a non-canonical marker".to_owned(),
                )
            })?;
            let Some(raw_uid) = name.strip_suffix(FENCE_SUFFIX) else {
                return Err(unsafe_fence());
            };
            let profile_uid = ProfileUid::parse(raw_uid.to_owned()).map_err(|_| {
                Error::PolicyRefused(
                    "automation profile fence directory contains a non-canonical marker".to_owned(),
                )
            })?;
            if paths.profile_automation_fence(&profile_uid) != entry.path() {
                return Err(Error::PolicyRefused(
                    "automation profile fence resolved to an unexpected path".to_owned(),
                ));
            }
            profile_uids.push(profile_uid);
        }
        profile_uids.sort();
        if profile_uids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::PolicyRefused(
                "automation profile fence directory contains duplicate identities".to_owned(),
            ));
        }
        if profile_uids.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut inspected = Vec::with_capacity(profile_uids.len());
        for profile_uid in profile_uids {
            let marker_path = paths.profile_automation_fence(&profile_uid);
            let marker = open_existing_marker(&marker_path, installation_uid, None, &profile_uid)?;
            let lifecycle_path = paths.profile_lifecycle_lock(&profile_uid);
            inspected.push(InspectedFence {
                profile_uid,
                marker_path,
                alias_refs: vec![marker.profile_ref.clone()],
                current_profile_ref: None,
                lifecycle_path,
                marker,
            });
        }
        let config_before = MetadataStore::new(paths.clone()).load_config()?;
        if &config_before.installation_uid != installation_uid {
            return Err(unsafe_fence());
        }
        for entry in &mut inspected {
            let current = current_profile_ref_for_uid(&config_before, &entry.profile_uid)?;
            if current.as_ref().is_some_and(|profile_ref| {
                profile_ref.provider() != entry.marker.profile_ref.provider()
            }) {
                return Err(unsafe_fence());
            }
            if let Some(profile_ref) = &current
                && profile_ref != &entry.marker.profile_ref
            {
                entry.alias_refs.push(profile_ref.clone());
            }
            entry.current_profile_ref = current;
        }
        reject_duplicate_aliases(paths, &inspected)?;

        let requests = inspected.iter().flat_map(|entry| {
            entry
                .alias_refs
                .iter()
                .map(|profile_ref| {
                    (
                        paths.profile_lock(profile_ref.provider(), profile_ref.name()),
                        true,
                    )
                })
                .chain(std::iter::once((entry.lifecycle_path.clone(), false)))
        });
        let mut held = match try_acquire_fence_lock_set(requests)? {
            FenceLockSetAcquisition::Acquired(held) => held,
            FenceLockSetAcquisition::Busy => return Err(Error::ConfigBusy),
        };
        let config_after = MetadataStore::new(paths.clone()).load_config()?;
        if &config_after.installation_uid != installation_uid {
            return Err(unsafe_fence());
        }
        for entry in &inspected {
            if current_profile_ref_for_uid(&config_after, &entry.profile_uid)?
                != entry.current_profile_ref
            {
                return Err(Error::ConfigBusy);
            }
        }

        let mut recovered = BTreeMap::new();
        for entry in inspected {
            let mut aliases = BTreeMap::new();
            for profile_ref in entry.alias_refs {
                let path = paths.profile_lock(profile_ref.provider(), profile_ref.name());
                let guard = held.remove(&path).ok_or_else(unsafe_fence)?;
                aliases.insert(profile_ref, guard);
            }
            let lifecycle = held
                .remove(&entry.lifecycle_path)
                .ok_or_else(unsafe_fence)?;
            let opened = open_existing_marker(
                &entry.marker_path,
                installation_uid,
                Some(&entry.marker.profile_ref),
                &entry.profile_uid,
            )?;
            if opened.bytes != entry.marker.bytes
                || opened.snapshot != entry.marker.snapshot
                || opened.fence_id != entry.marker.fence_id
            {
                return Err(unsafe_fence());
            }
            let binding = FenceBinding {
                installation_uid: installation_uid.clone(),
                profile_ref: opened.profile_ref,
                profile_uid: entry.profile_uid.clone(),
                fence_id: opened.fence_id,
                marker_bytes: opened.bytes,
                marker_snapshot: opened.snapshot,
                marker: opened.file,
                marker_path: entry.marker_path,
                lifecycle_path: entry.lifecycle_path,
            };
            validate_marker(&binding)?;
            recovered.insert(
                entry.profile_uid,
                ProfileAutomationFenceGuard {
                    binding,
                    legacy_aliases: RetainedProfileAliases { guards: aliases },
                    lifecycle,
                },
            );
        }
        if !held.is_empty() {
            return Err(unsafe_fence());
        }
        Ok(recovered)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reject_duplicate_aliases(paths: &AppPaths, inspected: &[InspectedFence]) -> Result<()> {
    let mut aliases = BTreeMap::new();
    for entry in inspected {
        for profile_ref in &entry.alias_refs {
            let path = paths.profile_lock(profile_ref.provider(), profile_ref.name());
            if aliases.insert(path, entry.profile_uid.clone()).is_some() {
                return Err(Error::PolicyRefused(
                    "automation profile fences bind one legacy alias to multiple UIDs".to_owned(),
                ));
            }
        }
    }
    Ok(())
}
