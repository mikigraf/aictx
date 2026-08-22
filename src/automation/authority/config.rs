use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

use serde::Deserialize;

use crate::{
    automation::contracts::{
        AgentRole, CallerSubject, EnvironmentName, HostIdentity, KeyId, ProfileUid, Provider,
        RepositoryId, Sha256Digest, TenantId, WorkspaceId,
    },
    binary::is_in_current_repository,
    config::{AppPaths, validate_sensitive_file},
    model::InstallationUid,
};

use super::{
    AUTHORITY_CONFIG_VERSION, AuthorityError, ControllerAttestation, ControllerCapacity,
    ControllerRateLimits, PreparedAuthority, PreparedController, PreparedSigningKey, RateLimit,
    ServiceLimits, signing::parse_verifying_key,
};

#[cfg(target_os = "linux")]
use super::LinuxPeerPolicy;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::config::validate_secure_directory;

const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MAX_KEYS: usize = 64;
const MAX_CONTROLLERS: usize = 64;
const MAX_SCOPE_ITEMS: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthorityConfig {
    version: u32,
    installation_uid: String,
    host_identity: String,
    service_limits: RawServiceLimits,
    failed_authentication_rate: RawRateLimit,
    signing_keys: Vec<RawSigningKey>,
    controllers: Vec<RawController>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServiceLimits {
    max_connections: u16,
    max_connections_per_controller: u16,
    max_frame_bytes: u32,
    read_timeout_milliseconds: u32,
    write_timeout_milliseconds: u32,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRateLimit {
    refill_per_minute: u32,
    burst: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSigningKey {
    key_id: String,
    algorithm: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawController {
    subject: String,
    tenant_ids: Vec<String>,
    signing_key_ids: Vec<String>,
    profile_uids: Vec<String>,
    providers: Vec<String>,
    environments: Vec<String>,
    roles: Vec<String>,
    repositories: Vec<String>,
    workspace_ids: Vec<String>,
    maximum_ttl_seconds: u64,
    maximum_session_seconds: u64,
    allow_authentication_exception: bool,
    allow_isolation_exception: bool,
    capacity: RawCapacity,
    rate_limits: RawControllerRateLimits,
    attestation: RawAttestation,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapacity {
    profile: u32,
    provider: u32,
    caller: u32,
    host: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawControllerRateLimits {
    acquire: RawRateLimit,
    readiness: RawRateLimit,
    principal_mismatch: RawRateLimit,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAttestation {
    mode: String,
    uid: Option<u32>,
    gid: Option<u32>,
    executable: Option<PathBuf>,
    executable_sha256: Option<String>,
    cgroup_v2_path: Option<String>,
    systemd_unit: Option<String>,
    acknowledged: Option<bool>,
}

impl PreparedAuthority {
    pub(crate) fn load(
        paths: &AppPaths,
        expected_installation_uid: &InstallationUid,
    ) -> Result<Self, AuthorityError> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (paths, expected_installation_uid);
            Err(AuthorityError::UnsupportedPlatform)
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            validate_secure_directory(&paths.config_dir)
                .map_err(|_| AuthorityError::UnsafeConfiguration)?;
            let bytes = read_bounded_authority_file(&paths.automation_authority_config())?;
            let text =
                std::str::from_utf8(&bytes).map_err(|_| AuthorityError::InvalidConfiguration)?;
            let raw: RawAuthorityConfig =
                toml::from_str(text).map_err(|_| AuthorityError::InvalidConfiguration)?;
            prepare(raw, expected_installation_uid, Sha256Digest::hash(&bytes))
        }
    }
}

fn read_bounded_authority_file(path: &Path) -> Result<Vec<u8>, AuthorityError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(AuthorityError::Unavailable);
        }
        Err(_) => return Err(AuthorityError::UnsafeConfiguration),
    }
    validate_sensitive_file(path).map_err(|_| AuthorityError::UnsafeConfiguration)?;
    #[cfg(unix)]
    let mut file = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| AuthorityError::UnsafeConfiguration)?,
    );
    #[cfg(not(unix))]
    let mut file = File::open(path).map_err(|_| AuthorityError::UnsafeConfiguration)?;
    let opened = file
        .metadata()
        .map_err(|_| AuthorityError::UnsafeConfiguration)?;
    validate_opened_file(path, &opened)?;
    if opened.len() > MAX_CONFIG_BYTES {
        return Err(AuthorityError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.by_ref()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthorityError::UnsafeConfiguration)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(AuthorityError::TooLarge);
    }
    let closed_snapshot = file
        .metadata()
        .map_err(|_| AuthorityError::UnsafeConfiguration)?;
    if !same_file_snapshot(&opened, &closed_snapshot) {
        return Err(AuthorityError::UnsafeConfiguration);
    }
    validate_sensitive_file(path).map_err(|_| AuthorityError::UnsafeConfiguration)?;
    let path_snapshot =
        fs::symlink_metadata(path).map_err(|_| AuthorityError::UnsafeConfiguration)?;
    if !same_file_identity(&opened, &path_snapshot) {
        return Err(AuthorityError::UnsafeConfiguration);
    }
    Ok(bytes)
}

fn validate_opened_file(path: &Path, metadata: &fs::Metadata) -> Result<(), AuthorityError> {
    if !metadata.is_file() {
        return Err(AuthorityError::UnsafeConfiguration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(AuthorityError::UnsafeConfiguration);
        }
        let path_metadata =
            fs::symlink_metadata(path).map_err(|_| AuthorityError::UnsafeConfiguration)?;
        if !same_file_identity(metadata, &path_metadata) {
            return Err(AuthorityError::UnsafeConfiguration);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    right.is_file() && left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_file() && right.is_file() && left.len() == right.len()
}

#[cfg(unix)]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    same_file_identity(left, right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
}

#[cfg(not(unix))]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_file_identity(left, right) && left.len() == right.len()
}

fn prepare(
    raw: RawAuthorityConfig,
    expected_installation_uid: &InstallationUid,
    configuration_digest: Sha256Digest,
) -> Result<PreparedAuthority, AuthorityError> {
    if raw.version != AUTHORITY_CONFIG_VERSION {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let installation_uid = InstallationUid::parse(raw.installation_uid)
        .map_err(|_| AuthorityError::InvalidConfiguration)?;
    if &installation_uid != expected_installation_uid {
        return Err(AuthorityError::InstallationMismatch);
    }
    let host_identity =
        HostIdentity::parse(raw.host_identity).map_err(|_| AuthorityError::InvalidConfiguration)?;
    let service_limits = prepare_service_limits(raw.service_limits)?;
    let failed_authentication_rate = prepare_rate(raw.failed_authentication_rate)?;
    if raw.signing_keys.is_empty() || raw.signing_keys.len() > MAX_KEYS {
        return Err(AuthorityError::InvalidConfiguration);
    }
    if raw.controllers.is_empty() || raw.controllers.len() > MAX_CONTROLLERS {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let mut key_ids = BTreeSet::new();
    let mut signing_keys = Vec::with_capacity(raw.signing_keys.len());
    for raw_key in raw.signing_keys {
        if raw_key.algorithm != "ed25519" {
            return Err(AuthorityError::InvalidConfiguration);
        }
        let key_id =
            KeyId::parse(raw_key.key_id).map_err(|_| AuthorityError::InvalidConfiguration)?;
        if !key_ids.insert(key_id.clone()) {
            return Err(AuthorityError::InvalidConfiguration);
        }
        signing_keys.push(PreparedSigningKey {
            key_id,
            verifying_key: parse_verifying_key(&raw_key.public_key)?,
        });
    }
    let mut subjects = BTreeSet::new();
    let mut attestation_fingerprints = HashSet::new();
    let mut controllers = Vec::with_capacity(raw.controllers.len());
    for raw_controller in raw.controllers {
        let controller = prepare_controller(raw_controller)?;
        if !subjects.insert(controller.subject.clone())
            || !attestation_fingerprints.insert(attestation_fingerprint(&controller.attestation))
            || !controller
                .signing_key_ids
                .iter()
                .all(|key_id| key_ids.contains(key_id))
        {
            return Err(AuthorityError::InvalidConfiguration);
        }
        controllers.push(controller);
    }
    if !key_ids.iter().all(|key_id| {
        controllers
            .iter()
            .any(|value| value.signing_key_ids.contains(key_id))
    }) {
        return Err(AuthorityError::InvalidConfiguration);
    }
    if controllers
        .iter()
        .filter(|value| {
            matches!(
                value.attestation,
                ControllerAttestation::MacosDevelopmentUnqualified
            )
        })
        .count()
        > 1
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    Ok(PreparedAuthority::from_parts(
        installation_uid,
        host_identity,
        service_limits,
        failed_authentication_rate,
        signing_keys,
        controllers,
        configuration_digest,
    ))
}

fn prepare_service_limits(raw: RawServiceLimits) -> Result<ServiceLimits, AuthorityError> {
    if raw.max_connections == 0
        || raw.max_connections > 1024
        || raw.max_connections_per_controller == 0
        || raw.max_connections_per_controller > raw.max_connections
        || !(1024..=1_048_576).contains(&raw.max_frame_bytes)
        || !(1..=30_000).contains(&raw.read_timeout_milliseconds)
        || !(1..=30_000).contains(&raw.write_timeout_milliseconds)
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    Ok(ServiceLimits {
        max_connections: raw.max_connections,
        max_connections_per_controller: raw.max_connections_per_controller,
        max_frame_bytes: raw.max_frame_bytes,
        read_timeout_milliseconds: raw.read_timeout_milliseconds,
        write_timeout_milliseconds: raw.write_timeout_milliseconds,
    })
}

fn prepare_rate(raw: RawRateLimit) -> Result<RateLimit, AuthorityError> {
    if !(1..=100_000).contains(&raw.refill_per_minute) || !(1..=100_000).contains(&raw.burst) {
        return Err(AuthorityError::InvalidConfiguration);
    }
    Ok(RateLimit {
        refill_per_minute: raw.refill_per_minute,
        burst: raw.burst,
    })
}

fn prepare_controller(raw: RawController) -> Result<PreparedController, AuthorityError> {
    let subject =
        CallerSubject::parse(raw.subject).map_err(|_| AuthorityError::InvalidConfiguration)?;
    let tenant_ids = parse_set(raw.tenant_ids, TenantId::parse)?;
    let signing_key_ids = parse_set(raw.signing_key_ids, KeyId::parse)?;
    let profile_uids = parse_set(raw.profile_uids, |value| {
        ProfileUid::parse(value).map_err(|_| ())
    })?;
    let providers = parse_set(raw.providers, |value| parse_provider(&value))?;
    let environments = parse_set(raw.environments, EnvironmentName::parse)?;
    let roles = parse_unique_vec(raw.roles, parse_role)?;
    let repositories = parse_set(raw.repositories, RepositoryId::parse)?;
    let workspace_ids = parse_set(raw.workspace_ids, WorkspaceId::parse)?;
    if raw.maximum_ttl_seconds == 0
        || raw.maximum_ttl_seconds > 86_400
        || raw.maximum_session_seconds < raw.maximum_ttl_seconds
        || raw.maximum_session_seconds > 604_800
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let capacity = prepare_capacity(raw.capacity)?;
    let rate_limits = ControllerRateLimits {
        acquire: prepare_rate(raw.rate_limits.acquire)?,
        readiness: prepare_rate(raw.rate_limits.readiness)?,
        principal_mismatch: prepare_rate(raw.rate_limits.principal_mismatch)?,
    };
    let attestation = prepare_attestation(raw.attestation, &environments)?;
    Ok(PreparedController {
        subject,
        tenant_ids,
        signing_key_ids,
        profile_uids,
        providers,
        environments,
        roles,
        repositories,
        workspace_ids,
        maximum_ttl_seconds: raw.maximum_ttl_seconds,
        maximum_session_seconds: raw.maximum_session_seconds,
        allow_authentication_exception: raw.allow_authentication_exception,
        allow_isolation_exception: raw.allow_isolation_exception,
        capacity,
        rate_limits,
        attestation,
    })
}

fn parse_set<T: Ord, E>(
    raw: Vec<String>,
    mut parser: impl FnMut(String) -> Result<T, E>,
) -> Result<BTreeSet<T>, AuthorityError> {
    if raw.is_empty() || raw.len() > MAX_SCOPE_ITEMS || raw.iter().any(|value| value == "*") {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let mut output = BTreeSet::new();
    for value in raw {
        let parsed = parser(value).map_err(|_| AuthorityError::InvalidConfiguration)?;
        if !output.insert(parsed) {
            return Err(AuthorityError::InvalidConfiguration);
        }
    }
    Ok(output)
}

fn parse_unique_vec<T: PartialEq, E>(
    raw: Vec<String>,
    mut parser: impl FnMut(&str) -> Result<T, E>,
) -> Result<Vec<T>, AuthorityError> {
    if raw.is_empty() || raw.len() > MAX_SCOPE_ITEMS || raw.iter().any(|value| value == "*") {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let mut output = Vec::with_capacity(raw.len());
    for value in raw {
        let parsed = parser(&value).map_err(|_| AuthorityError::InvalidConfiguration)?;
        if output.contains(&parsed) {
            return Err(AuthorityError::InvalidConfiguration);
        }
        output.push(parsed);
    }
    Ok(output)
}

fn parse_provider(value: &str) -> Result<Provider, ()> {
    match value {
        "claude" => Ok(Provider::Claude),
        "codex" => Ok(Provider::Codex),
        _ => Err(()),
    }
}

fn parse_role(value: &str) -> Result<AgentRole, ()> {
    match value {
        "implementer" => Ok(AgentRole::Implementer),
        "local-reviewer" => Ok(AgentRole::LocalReviewer),
        "pr-reviewer" => Ok(AgentRole::PrReviewer),
        _ => Err(()),
    }
}

fn prepare_capacity(raw: RawCapacity) -> Result<ControllerCapacity, AuthorityError> {
    if [raw.profile, raw.provider, raw.caller, raw.host]
        .into_iter()
        .any(|value| !(1..=1_000_000).contains(&value))
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    Ok(ControllerCapacity {
        profile: raw.profile,
        provider: raw.provider,
        caller: raw.caller,
        host: raw.host,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn prepare_attestation(
    raw: RawAttestation,
    environments: &BTreeSet<EnvironmentName>,
) -> Result<ControllerAttestation, AuthorityError> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (raw, environments);
        Err(AuthorityError::InvalidConfiguration)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[cfg(target_os = "linux")]
    let _ = environments;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match raw.mode.as_str() {
        "linux-peer-v1" => {
            #[cfg(not(target_os = "linux"))]
            return Err(AuthorityError::InvalidConfiguration);
            #[cfg(target_os = "linux")]
            {
                if raw.acknowledged.is_some() {
                    return Err(AuthorityError::InvalidConfiguration);
                }
                let executable = raw.executable.ok_or(AuthorityError::InvalidConfiguration)?;
                validate_executable_syntax(&executable)?;
                let executable_sha256 = raw
                    .executable_sha256
                    .ok_or(AuthorityError::InvalidConfiguration)?
                    .parse::<Sha256Digest>()
                    .map_err(|_| AuthorityError::InvalidConfiguration)?;
                let cgroup_v2_path = raw
                    .cgroup_v2_path
                    .ok_or(AuthorityError::InvalidConfiguration)?;
                let systemd_unit = raw
                    .systemd_unit
                    .ok_or(AuthorityError::InvalidConfiguration)?;
                validate_cgroup(&cgroup_v2_path, &systemd_unit)?;
                let (executable, executable_device, executable_inode) =
                    prepare_linux_executable(&executable, executable_sha256)?;
                Ok(ControllerAttestation::LinuxPeer(LinuxPeerPolicy {
                    uid: raw.uid.ok_or(AuthorityError::InvalidConfiguration)?,
                    gid: raw.gid.ok_or(AuthorityError::InvalidConfiguration)?,
                    executable,
                    executable_sha256,
                    cgroup_v2_path,
                    systemd_unit,
                    executable_device,
                    executable_inode,
                }))
            }
        }
        "macos-development-unqualified-v1" => {
            #[cfg(not(target_os = "macos"))]
            return Err(AuthorityError::InvalidConfiguration);
            #[cfg(target_os = "macos")]
            {
                if raw.acknowledged != Some(true)
                    || raw.uid.is_some()
                    || raw.gid.is_some()
                    || raw.executable.is_some()
                    || raw.executable_sha256.is_some()
                    || raw.cgroup_v2_path.is_some()
                    || raw.systemd_unit.is_some()
                    || environments.len() != 1
                    || environments
                        .iter()
                        .next()
                        .is_none_or(|value| value.as_str() != "local-development")
                {
                    return Err(AuthorityError::InvalidConfiguration);
                }
                Ok(ControllerAttestation::MacosDevelopmentUnqualified)
            }
        }
        _ => Err(AuthorityError::InvalidConfiguration),
    }
}

#[cfg(target_os = "linux")]
fn prepare_linux_executable(
    path: &Path,
    expected_digest: Sha256Digest,
) -> Result<(PathBuf, u64, u64), AuthorityError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use sha2::{Digest, Sha256};

    use crate::config::{LeafOwnership, validate_trusted_path_chain};

    let canonical = path
        .canonicalize()
        .map_err(|_| AuthorityError::InvalidConfiguration)?;
    if canonical != path
        || canonical
            .ancestors()
            .any(|ancestor| fs::symlink_metadata(ancestor.join(".git")).is_ok())
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    validate_trusted_path_chain(&canonical, LeafOwnership::CurrentUserOrRoot)
        .map_err(|_| AuthorityError::InvalidConfiguration)?;
    let mut file = File::from(
        rustix::fs::open(
            &canonical,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| AuthorityError::InvalidConfiguration)?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| AuthorityError::InvalidConfiguration)?;
    let path_metadata =
        fs::symlink_metadata(&canonical).map_err(|_| AuthorityError::InvalidConfiguration)?;
    if !metadata.is_file()
        || !same_file_identity(&metadata, &path_metadata)
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o222 != 0
        || metadata.nlink() != 1
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)
        .map_err(|_| AuthorityError::InvalidConfiguration)?;
    if magic != *b"\x7fELF" {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let mut hasher = Sha256::new();
    hasher.update(magic);
    let mut total = 4_u64;
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| AuthorityError::InvalidConfiguration)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or(AuthorityError::InvalidConfiguration)?;
        if total > 536_870_912 {
            return Err(AuthorityError::InvalidConfiguration);
        }
        hasher.update(&buffer[..count]);
    }
    let hashed_snapshot = file
        .metadata()
        .map_err(|_| AuthorityError::InvalidConfiguration)?;
    let final_path_snapshot =
        fs::symlink_metadata(&canonical).map_err(|_| AuthorityError::InvalidConfiguration)?;
    if !same_file_snapshot(&metadata, &hashed_snapshot)
        || !same_file_identity(&hashed_snapshot, &final_path_snapshot)
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let digest = format!("sha256:{:x}", hasher.finalize())
        .parse::<Sha256Digest>()
        .map_err(|_| AuthorityError::InvalidConfiguration)?;
    if digest != expected_digest {
        return Err(AuthorityError::InvalidConfiguration);
    }
    Ok((canonical, metadata.dev(), metadata.ino()))
}

fn validate_executable_syntax(path: &Path) -> Result<(), AuthorityError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || is_in_current_repository(path)
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_cgroup(path: &str, unit: &str) -> Result<(), AuthorityError> {
    let valid_unit = unit.ends_with(".service")
        && !unit.is_empty()
        && unit.len() <= 128
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'));
    let valid_path = path.starts_with('/')
        && path.len() <= 4096
        && !path.contains(['\n', '\r', '\0'])
        && path
            .split('/')
            .skip(1)
            .all(|component| !matches!(component, "" | "." | ".."));
    if !valid_unit
        || !valid_path
        || Path::new(path).file_name().and_then(|value| value.to_str()) != Some(unit)
    {
        return Err(AuthorityError::InvalidConfiguration);
    }
    Ok(())
}

fn attestation_fingerprint(attestation: &ControllerAttestation) -> String {
    match attestation {
        ControllerAttestation::LinuxPeer(value) => format!(
            "linux\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            value.uid,
            value.gid,
            value.executable.display(),
            value.executable_sha256,
            value.cgroup_v2_path,
            value.systemd_unit,
            value.executable_device,
            value.executable_inode
        ),
        ControllerAttestation::MacosDevelopmentUnqualified => "macos-development".to_owned(),
    }
}
