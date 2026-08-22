use std::{
    fs::{self, File},
    io::Read,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{
    automation::{
        authority::{LinuxPeerPolicy, PreparedAuthority},
        contracts::Sha256Digest,
    },
    config::{LeafOwnership, validate_trusted_path_chain},
};

use super::{AttestationError, AuthenticatedCaller};

#[path = "linux_snapshot.rs"]
mod snapshot;
use snapshot::{ExecutableSnapshot, attestation_binding, matches_retained_executable};

const MAX_PROC_TEXT_BYTES: u64 = 65_536;
const MAX_EXECUTABLE_BYTES: u64 = 536_870_912;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PeerCredentials {
    pid: rustix::process::Pid,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessIds {
    pid: u32,
    uids: [u32; 4],
    gids: [u32; 4],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessObservation {
    ids_before: ProcessIds,
    ids_after: ProcessIds,
    start_time_before: u64,
    start_time_after: u64,
    executable_path: PathBuf,
    executable_digest: Option<Sha256Digest>,
    executable_snapshot: ExecutableSnapshot,
    cgroup_v2_path: String,
    cgroup_device: u64,
    cgroup_inode: u64,
    boot_id: String,
}

pub(super) struct LinuxProcessGuard {
    pidfd: OwnedFd,
    credentials: PeerCredentials,
    executable_snapshot: ExecutableSnapshot,
}

pub(crate) struct LinuxAttestor;

impl LinuxAttestor {
    /// Attest the process that opened `stream`.
    ///
    /// This does not establish the identity of every later stream writer.
    /// Before authorizing a frame, a future listener must enable credential
    /// passing and match that frame's credentials to the retained process
    /// identity. Listener and framing integration are intentionally out of
    /// scope here.
    pub(crate) fn attest(
        stream: &UnixStream,
        authority: &PreparedAuthority,
    ) -> Result<AuthenticatedCaller, AttestationError> {
        validate_procfs()?;
        let (credentials, pidfd) = extract_peer_identity(stream)?;
        if !authority.controllers().iter().any(|controller| {
            controller.linux_peer_policy().is_some_and(|policy| {
                policy.uid() == credentials.uid && policy.gid() == credentials.gid
            })
        }) {
            return Err(AttestationError::CallerAuthenticationFailed);
        }
        validate_pidfd(&pidfd, credentials.pid)?;
        let cheap_observation = observe_process(credentials.pid, false)?;
        validate_pidfd(&pidfd, credentials.pid)?;
        let mut matches = authority.controllers().iter().filter(|controller| {
            let Some(policy) = controller.linux_peer_policy() else {
                return false;
            };
            policy.uid() == credentials.uid
                && policy.gid() == credentials.gid
                && matches_controller(policy, credentials, &cheap_observation)
        });
        let controller = matches
            .next()
            .filter(|_| matches.next().is_none())
            .ok_or(AttestationError::CallerAuthenticationFailed)?
            .clone();
        let observation = observe_process(credentials.pid, true)?;
        let Some(policy) = controller.linux_peer_policy() else {
            return Err(AttestationError::CallerAuthenticationFailed);
        };
        if !matches_controller(policy, credentials, &observation) {
            return Err(AttestationError::CallerAuthenticationFailed);
        }
        validate_pidfd(&pidfd, credentials.pid)?;
        let binding = attestation_binding(
            authority,
            controller.subject(),
            policy,
            credentials,
            &observation,
        );
        let executable_snapshot = observation.executable_snapshot;
        Ok(AuthenticatedCaller::linux(
            authority,
            controller,
            binding,
            LinuxProcessGuard {
                pidfd,
                credentials,
                executable_snapshot,
            },
        ))
    }
}

fn extract_peer_identity(
    stream: &UnixStream,
) -> Result<(PeerCredentials, OwnedFd), AttestationError> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    let credentials = PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid.as_raw(),
        gid: credentials.gid.as_raw(),
    };
    let pidfd =
        extract_peer_pidfd(stream).map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    validate_pidfd(&pidfd, credentials.pid)?;
    Ok((credentials, pidfd))
}

fn extract_peer_pidfd(stream: &UnixStream) -> nix::Result<OwnedFd> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerPidfd)
}

pub(super) fn revalidate(
    caller: &AuthenticatedCaller,
    authority: &PreparedAuthority,
) -> Result<(), AttestationError> {
    validate_procfs()?;
    validate_pidfd(
        &caller.process_guard.pidfd,
        caller.process_guard.credentials.pid,
    )?;
    let observation = observe_process(caller.process_guard.credentials.pid, false)?;
    validate_pidfd(
        &caller.process_guard.pidfd,
        caller.process_guard.credentials.pid,
    )?;
    let Some(policy) = caller.controller.linux_peer_policy() else {
        return Err(AttestationError::CallerAuthenticationFailed);
    };
    if !matches_retained_executable(
        caller.process_guard.executable_snapshot,
        observation.executable_snapshot,
    ) || !matches_controller(policy, caller.process_guard.credentials, &observation)
        || attestation_binding(
            authority,
            caller.controller.subject(),
            policy,
            caller.process_guard.credentials,
            &observation,
        ) != caller.attestation_binding
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(())
}

fn observe_process(
    pid: rustix::process::Pid,
    hash_content: bool,
) -> Result<ProcessObservation, AttestationError> {
    let proc_root = PathBuf::from(format!("/proc/{}", pid.as_raw_pid()));
    let boot_id_before = read_boot_id()?;
    let ids_before = read_status_ids(&proc_root.join("status"))?;
    let start_time_before = read_live_start_time(&proc_root.join("stat"))?;
    let cgroup_v2_path = read_unified_cgroup(&proc_root.join("cgroup"))?;
    let cgroup_before = validate_protected_cgroup(&cgroup_v2_path)?;
    let executable_link = proc_root.join("exe");
    let executable_path = fs::read_link(&executable_link)
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    validate_proc_executable_path(&executable_path)?;
    let mut executable =
        File::open(&executable_link).map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    let executable_metadata = executable
        .metadata()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    validate_observed_executable(&executable_metadata)?;
    let executable_digest = if hash_content {
        Some(hash_executable(&mut executable, executable_metadata.len())?)
    } else {
        None
    };
    let hashed_snapshot = executable
        .metadata()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if !same_executable_snapshot(&executable_metadata, &hashed_snapshot) {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let ids_after = read_status_ids(&proc_root.join("status"))?;
    let start_time_after = read_live_start_time(&proc_root.join("stat"))?;
    let cgroup_after_path = read_unified_cgroup(&proc_root.join("cgroup"))?;
    let cgroup_after = validate_protected_cgroup(&cgroup_after_path)?;
    let final_executable_path = fs::read_link(&executable_link)
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    validate_proc_executable_path(&final_executable_path)?;
    let final_executable =
        File::open(&executable_link).map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    let final_executable_metadata = final_executable
        .metadata()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    validate_observed_executable(&final_executable_metadata)?;
    let boot_id_after = read_boot_id()?;
    if executable_path != final_executable_path
        || !same_executable_snapshot(&hashed_snapshot, &final_executable_metadata)
        || cgroup_v2_path != cgroup_after_path
        || cgroup_before != cgroup_after
        || boot_id_before != boot_id_after
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(ProcessObservation {
        ids_before,
        ids_after,
        start_time_before,
        start_time_after,
        executable_path,
        executable_digest,
        executable_snapshot: ExecutableSnapshot::from_metadata(&executable_metadata),
        cgroup_v2_path,
        cgroup_device: cgroup_before.0,
        cgroup_inode: cgroup_before.1,
        boot_id: boot_id_before,
    })
}

fn validate_proc_executable_path(path: &Path) -> Result<(), AttestationError> {
    if !path.is_absolute() || path.as_os_str().to_string_lossy().ends_with(" (deleted)") {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(())
}

fn validate_observed_executable(metadata: &fs::Metadata) -> Result<(), AttestationError> {
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o222 != 0
        || metadata.nlink() != 1
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(())
}

fn same_executable_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && ExecutableSnapshot::from_metadata(left) == ExecutableSnapshot::from_metadata(right)
}

fn matches_controller(
    policy: &LinuxPeerPolicy,
    credentials: PeerCredentials,
    observation: &ProcessObservation,
) -> bool {
    matches_observation(policy, credentials, observation)
        && validate_expected_executable(policy).is_ok()
}

fn matches_observation(
    policy: &LinuxPeerPolicy,
    credentials: PeerCredentials,
    observation: &ProcessObservation,
) -> bool {
    let expected_ids = ProcessIds {
        pid: credentials.pid.as_raw_pid().cast_unsigned(),
        uids: [credentials.uid; 4],
        gids: [credentials.gid; 4],
    };
    policy.uid() == credentials.uid
        && policy.gid() == credentials.gid
        && observation.ids_before == expected_ids
        && observation.ids_after == expected_ids
        && observation.start_time_before != 0
        && observation.start_time_before == observation.start_time_after
        && observation.executable_path == policy.executable()
        && observation
            .executable_digest
            .is_none_or(|digest| digest == policy.executable_sha256())
        && observation.executable_snapshot.device == policy.executable_device()
        && observation.executable_snapshot.inode == policy.executable_inode()
        && observation.cgroup_v2_path == policy.cgroup_v2_path()
        && Path::new(&observation.cgroup_v2_path)
            .file_name()
            .and_then(|value| value.to_str())
            == Some(policy.systemd_unit())
}

fn validate_expected_executable(policy: &LinuxPeerPolicy) -> Result<(), AttestationError> {
    validate_trusted_path_chain(policy.executable(), LeafOwnership::CurrentUserOrRoot)
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    let canonical = policy
        .executable()
        .canonicalize()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if canonical != policy.executable() {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    if canonical
        .ancestors()
        .any(|ancestor| fs::symlink_metadata(ancestor.join(".git")).is_ok())
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let metadata = fs::symlink_metadata(policy.executable())
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if !metadata.is_file()
        || metadata.dev() != policy.executable_device()
        || metadata.ino() != policy.executable_inode()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o222 != 0
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(())
}

fn validate_procfs() -> Result<(), AttestationError> {
    let metadata =
        fs::symlink_metadata("/proc").map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    let filesystem =
        rustix::fs::statfs("/proc").map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if !metadata.is_dir() || filesystem.f_type != rustix::fs::PROC_SUPER_MAGIC {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(())
}

fn validate_pidfd(
    pidfd: &OwnedFd,
    expected_pid: rustix::process::Pid,
) -> Result<(), AttestationError> {
    let mut descriptors = [rustix::event::PollFd::new(
        pidfd,
        rustix::event::PollFlags::IN,
    )];
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ready = rustix::event::poll(&mut descriptors, Some(&zero))
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if ready != 0 || !descriptors[0].revents().is_empty() {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let fdinfo = PathBuf::from(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()));
    let text = read_bounded_utf8(&fdinfo)?;
    let observed_pid = parse_unique_label(&text, "Pid:")?
        .parse::<i32>()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if observed_pid != expected_pid.as_raw_pid() {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let ready = rustix::event::poll(&mut descriptors, Some(&zero))
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if ready != 0 || !descriptors[0].revents().is_empty() {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(())
}

fn validate_protected_cgroup(path: &str) -> Result<(u64, u64), AttestationError> {
    const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
    let root = Path::new("/sys/fs/cgroup");
    let filesystem =
        rustix::fs::statfs(root).map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if u64::try_from(filesystem.f_type).ok() != Some(CGROUP2_SUPER_MAGIC) {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let relative = path
        .strip_prefix('/')
        .ok_or(AttestationError::CallerAuthenticationFailed)?;
    let directory = root.join(relative);
    if directory
        .canonicalize()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?
        != directory
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let mut cursor = directory.as_path();
    loop {
        let metadata = fs::symlink_metadata(cursor)
            .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(AttestationError::CallerAuthenticationFailed);
        }
        if cursor == root {
            break;
        }
        cursor = cursor
            .parent()
            .ok_or(AttestationError::CallerAuthenticationFailed)?;
        if !cursor.starts_with(root) {
            return Err(AttestationError::CallerAuthenticationFailed);
        }
    }
    for control in ["cgroup.procs", "cgroup.threads"] {
        let metadata = fs::symlink_metadata(directory.join(control))
            .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(AttestationError::CallerAuthenticationFailed);
        }
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn read_boot_id() -> Result<String, AttestationError> {
    let value = read_bounded_utf8(Path::new("/proc/sys/kernel/random/boot_id"))?;
    let value = value.trim_end_matches('\n');
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        });
    if !valid {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(value.to_owned())
}

fn read_status_ids(path: &Path) -> Result<ProcessIds, AttestationError> {
    let text = read_bounded_utf8(path)?;
    let pid = parse_status_pid(&text)?;
    let uids = parse_status_ids(&text, "Uid:")?;
    let gids = parse_status_ids(&text, "Gid:")?;
    Ok(ProcessIds { pid, uids, gids })
}

fn parse_status_pid(text: &str) -> Result<u32, AttestationError> {
    parse_unique_label(text, "Pid:")?
        .parse::<u32>()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)
}

fn parse_status_ids(text: &str, label: &str) -> Result<[u32; 4], AttestationError> {
    let values = parse_unique_label(text, label)?
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    values
        .try_into()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)
}

fn parse_unique_label<'a>(text: &'a str, label: &str) -> Result<&'a str, AttestationError> {
    let mut values = text
        .lines()
        .filter_map(|line| line.strip_prefix(label).map(str::trim));
    let value = values
        .next()
        .ok_or(AttestationError::CallerAuthenticationFailed)?;
    if values.next().is_some() || value.is_empty() {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(value)
}

fn read_live_start_time(path: &Path) -> Result<u64, AttestationError> {
    let stat = read_bounded_utf8(path)?;
    parse_live_start_time(&stat)
}

fn parse_live_start_time(stat: &str) -> Result<u64, AttestationError> {
    let closing = stat
        .rfind(')')
        .ok_or(AttestationError::CallerAuthenticationFailed)?;
    let mut fields = stat
        .get(closing + 1..)
        .ok_or(AttestationError::CallerAuthenticationFailed)?
        .split_ascii_whitespace();
    let state = fields
        .next()
        .ok_or(AttestationError::CallerAuthenticationFailed)?
        .as_bytes();
    if !matches!(
        state,
        [b'R' | b'S' | b'D' | b'T' | b't' | b'W' | b'K' | b'P' | b'I']
    ) {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    fields
        .nth(18)
        .ok_or(AttestationError::CallerAuthenticationFailed)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(AttestationError::CallerAuthenticationFailed)
}

fn read_unified_cgroup(path: &Path) -> Result<String, AttestationError> {
    let text = read_bounded_utf8(path)?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let value = lines[0]
        .strip_prefix("0::")
        .filter(|value| value.starts_with('/') && !value.contains('\r') && !value.contains('\0'))
        .ok_or(AttestationError::CallerAuthenticationFailed)?;
    if value
        .split('/')
        .skip(1)
        .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    Ok(value.to_owned())
}

fn read_bounded_utf8(path: &Path) -> Result<String, AttestationError> {
    let mut file = File::open(path).map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PROC_TEXT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PROC_TEXT_BYTES {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    String::from_utf8(bytes).map_err(|_| AttestationError::CallerAuthenticationFailed)
}

fn hash_executable(file: &mut File, size: u64) -> Result<Sha256Digest, AttestationError> {
    if size == 0 || size > MAX_EXECUTABLE_BYTES {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| AttestationError::CallerAuthenticationFailed)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or(AttestationError::CallerAuthenticationFailed)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(AttestationError::CallerAuthenticationFailed);
        }
        hasher.update(&buffer[..count]);
    }
    if total != size {
        return Err(AttestationError::CallerAuthenticationFailed);
    }
    format!("sha256:{:x}", hasher.finalize())
        .parse::<Sha256Digest>()
        .map_err(|_| AttestationError::CallerAuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        format!("sha256:{}", byte.to_string().repeat(64))
            .parse()
            .unwrap_or_else(|error| panic!("digest: {error:?}"))
    }

    fn policy() -> LinuxPeerPolicy {
        LinuxPeerPolicy::test_fixture(
            PathBuf::from("/opt/controller"),
            digest('a'),
            "/system.slice/controller.service".to_owned(),
            "controller.service".to_owned(),
        )
    }

    fn credentials() -> PeerCredentials {
        PeerCredentials {
            pid: rustix::process::Pid::from_raw(42)
                .unwrap_or_else(|| panic!("positive fixture pid")),
            uid: 1000,
            gid: 1000,
        }
    }

    fn observation() -> ProcessObservation {
        ProcessObservation {
            ids_before: ProcessIds {
                pid: 42,
                uids: [1000; 4],
                gids: [1000; 4],
            },
            ids_after: ProcessIds {
                pid: 42,
                uids: [1000; 4],
                gids: [1000; 4],
            },
            start_time_before: 99,
            start_time_after: 99,
            executable_path: PathBuf::from("/opt/controller"),
            executable_digest: Some(digest('a')),
            executable_snapshot: ExecutableSnapshot {
                device: 10,
                inode: 20,
                length: 30,
                modified_seconds: 40,
                modified_nanoseconds: 50,
                changed_seconds: 60,
                changed_nanoseconds: 70,
                mode: 0o100_555,
                uid: 1000,
                gid: 1000,
                link_count: 1,
            },
            cgroup_v2_path: "/system.slice/controller.service".to_owned(),
            cgroup_device: 30,
            cgroup_inode: 40,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        }
    }

    #[test]
    fn matcher_rejects_every_changed_kernel_or_executable_signal() {
        let policy = policy();
        let credentials = credentials();
        let original = observation();
        assert!(matches_observation(&policy, credentials, &original));

        let mut cases = Vec::new();
        let mut value = original.clone();
        value.ids_before.pid += 1;
        cases.push(value);
        let mut value = original.clone();
        value.ids_before.uids[0] = 1001;
        cases.push(value);
        let mut value = original.clone();
        value.ids_after.gids[3] = 1001;
        cases.push(value);
        let mut value = original.clone();
        value.start_time_after += 1;
        cases.push(value);
        let mut value = original.clone();
        value.executable_path.push("deleted");
        cases.push(value);
        let mut value = original.clone();
        value.executable_digest = Some(digest('b'));
        cases.push(value);
        let mut value = original.clone();
        value.executable_snapshot.device += 1;
        cases.push(value);
        let mut value = original.clone();
        value.executable_snapshot.inode += 1;
        cases.push(value);
        let mut value = original.clone();
        value.cgroup_v2_path = "/system.slice/other.service".to_owned();
        cases.push(value);
        assert!(
            cases
                .iter()
                .all(|value| !matches_observation(&policy, credentials, value))
        );
        let mut changed_credentials = credentials;
        changed_credentials.uid += 1;
        assert!(!matches_observation(
            &policy,
            changed_credentials,
            &original
        ));
        let mut changed_credentials = credentials;
        changed_credentials.gid += 1;
        assert!(!matches_observation(
            &policy,
            changed_credentials,
            &original
        ));
    }

    #[test]
    fn cgroup_parser_requires_one_unified_v2_record() {
        for invalid in ["", "1:name:/x\n", "0::/x\n0::/y\n", "0::/x//y\n"] {
            let temporary =
                tempfile::NamedTempFile::new().unwrap_or_else(|error| panic!("tempfile: {error}"));
            fs::write(temporary.path(), invalid)
                .unwrap_or_else(|error| panic!("write cgroup fixture: {error}"));
            assert!(read_unified_cgroup(temporary.path()).is_err());
        }
    }

    #[test]
    fn proc_parsers_reject_duplicate_ids_and_non_live_states() {
        assert!(parse_status_ids("Uid:\t1 1 1 1\nUid:\t1 1 1 1\n", "Uid:").is_err());
        assert!(parse_status_pid("Pid:\t42\nPid:\t42\n").is_err());
        let stat = |state: &str, start: &str| {
            format!(
                "42 (controller) {state} {} {start}",
                vec!["1"; 18].join(" ")
            )
        };
        for state in ["R", "S", "D", "T", "t", "W", "K", "P", "I"] {
            assert_eq!(parse_live_start_time(&stat(state, "99")), Ok(99));
        }
        for state in ["Z", "X", "x", "?", "RR"] {
            assert!(parse_live_start_time(&stat(state, "99")).is_err());
        }
        assert!(parse_live_start_time(&stat("R", "0")).is_err());
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn native_socket_peer_credentials_are_kernel_derived() {
        let (left, right) =
            UnixStream::pair().unwrap_or_else(|error| panic!("socket pair: {error}"));
        let left_credentials = rustix::net::sockopt::socket_peercred(&left)
            .unwrap_or_else(|error| panic!("left peer credentials: {error:?}"));
        let right_credentials = rustix::net::sockopt::socket_peercred(&right)
            .unwrap_or_else(|error| panic!("right peer credentials: {error:?}"));
        let current_pid = rustix::process::getpid();
        let current_uid = rustix::process::getuid().as_raw();
        let current_gid = rustix::process::getgid().as_raw();
        assert_eq!(left_credentials.pid, current_pid);
        assert_eq!(right_credentials.pid, current_pid);
        assert_eq!(
            (left_credentials.uid.as_raw(), left_credentials.gid.as_raw()),
            (current_uid, current_gid)
        );
        assert_eq!(
            (
                right_credentials.uid.as_raw(),
                right_credentials.gid.as_raw()
            ),
            (current_uid, current_gid)
        );
        for stream in [&left, &right] {
            match extract_peer_pidfd(stream) {
                Ok(pidfd) => validate_pidfd(&pidfd, current_pid)
                    .unwrap_or_else(|error| panic!("live peer pidfd: {error:?}")),
                Err(nix::errno::Errno::ENOPROTOOPT)
                    if std::env::var_os("CTXLANE_REQUIRE_SO_PEERPIDFD").is_none() => {}
                Err(error) => panic!("SO_PEERPIDFD kernel qualification failed: {error}"),
            }
        }
    }
}
