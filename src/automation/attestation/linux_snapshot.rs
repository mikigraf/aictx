use std::{fs, os::unix::fs::MetadataExt};

use crate::automation::{
    authority::{LinuxPeerPolicy, PreparedAuthority},
    contracts::{CallerSubject, Sha256Digest},
};

use super::{PeerCredentials, ProcessObservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExecutableSnapshot {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) length: u64,
    pub(super) modified_seconds: i64,
    pub(super) modified_nanoseconds: i64,
    pub(super) changed_seconds: i64,
    pub(super) changed_nanoseconds: i64,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) link_count: u64,
}

impl ExecutableSnapshot {
    pub(super) fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            link_count: metadata.nlink(),
        }
    }
}

pub(super) fn matches_retained_executable(
    retained: ExecutableSnapshot,
    observed: ExecutableSnapshot,
) -> bool {
    retained == observed
}

pub(super) fn attestation_binding(
    authority: &PreparedAuthority,
    subject: &CallerSubject,
    policy: &LinuxPeerPolicy,
    credentials: PeerCredentials,
    observation: &ProcessObservation,
) -> Sha256Digest {
    let mut material = b"ctxlane.linux-peer-attestation/v2\0".to_vec();
    let snapshot = observation.executable_snapshot;
    for field in [
        authority.host_identity().as_str().to_owned(),
        subject.as_str().to_owned(),
        authority.configuration_digest().to_string(),
        credentials.pid.as_raw_pid().to_string(),
        credentials.uid.to_string(),
        credentials.gid.to_string(),
        observation.start_time_after.to_string(),
        snapshot.device.to_string(),
        snapshot.inode.to_string(),
        snapshot.length.to_string(),
        snapshot.modified_seconds.to_string(),
        snapshot.modified_nanoseconds.to_string(),
        snapshot.changed_seconds.to_string(),
        snapshot.changed_nanoseconds.to_string(),
        snapshot.mode.to_string(),
        snapshot.uid.to_string(),
        snapshot.gid.to_string(),
        snapshot.link_count.to_string(),
        observation
            .executable_digest
            .unwrap_or(policy.executable_sha256())
            .to_string(),
        observation.cgroup_v2_path.clone(),
        observation.cgroup_device.to_string(),
        observation.cgroup_inode.to_string(),
        observation.boot_id.clone(),
    ] {
        material.extend_from_slice(field.as_bytes());
        material.push(0);
    }
    Sha256Digest::hash(material)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> ExecutableSnapshot {
        ExecutableSnapshot {
            device: 1,
            inode: 2,
            length: 3,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
            mode: 0o100_555,
            uid: 8,
            gid: 9,
            link_count: 1,
        }
    }

    #[test]
    fn every_executable_snapshot_field_is_identity_bearing() {
        let retained = snapshot();
        assert!(matches_retained_executable(retained, retained));
        let mut variants = Vec::new();
        macro_rules! changed {
            ($field:ident) => {{
                let mut value = retained;
                value.$field += 1;
                variants.push(value);
            }};
        }
        changed!(device);
        changed!(inode);
        changed!(length);
        changed!(modified_seconds);
        changed!(modified_nanoseconds);
        changed!(changed_seconds);
        changed!(changed_nanoseconds);
        changed!(mode);
        changed!(uid);
        changed!(gid);
        changed!(link_count);
        assert!(
            variants
                .into_iter()
                .all(|value| !matches_retained_executable(retained, value))
        );
    }
}
