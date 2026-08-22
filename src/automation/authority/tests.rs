use std::{
    fmt::Write as _,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    str::FromStr,
};

use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            AgentRole, DetachedSignature, DurationSeconds, MaximumTtlSeconds, Provider,
            WorkOrderAuthorization, WorkOrderAuthorizationSchema, WorkOrderProofAlgorithm,
        },
        policy::AllowScope,
    },
    config::AppPaths,
    model::InstallationUid,
};

use super::{AuthenticationAssurance, AuthorityError, PreparedAuthority, ProofError};

#[cfg(target_os = "macos")]
use crate::automation::contracts::Sha256Digest;
#[cfg(target_os = "macos")]
use ed25519_dalek::{Signer, SigningKey};

mod negative_tests;

const INSTALLATION: &str = "installation_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const PUBLIC_KEY: &str = "3e7ac95170ac322c7cbd342e12e5e0af36f21375ed128c33372e73810d05bff9";

#[test]
fn connection_level_linux_attestation_is_not_verifier_eligible() {
    assert!(!AuthenticationAssurance::LinuxConnectionAttested.permits_work_order_verification());
    assert!(AuthenticationAssurance::MacosDevelopmentUnqualified.permits_work_order_verification());
}

struct Fixture {
    _temporary: TempDir,
    paths: AppPaths,
    installation_uid: InstallationUid,
    source: String,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
        fs::create_dir_all(&paths.config_dir)
            .unwrap_or_else(|error| panic!("config directory: {error}"));
        set_mode(&paths.config_dir, 0o700);
        let source = valid_platform_config(&temporary);
        let installation_uid = parsed(INSTALLATION);
        let fixture = Self {
            _temporary: temporary,
            paths,
            installation_uid,
            source,
        };
        fixture.write();
        fixture
    }

    fn write(&self) {
        fs::write(self.paths.automation_authority_config(), &self.source)
            .unwrap_or_else(|error| panic!("authority fixture: {error}"));
        set_mode(&self.paths.automation_authority_config(), 0o600);
    }

    fn load(&self) -> Result<PreparedAuthority, AuthorityError> {
        PreparedAuthority::load(&self.paths, &self.installation_uid)
    }

    fn assert_invalid(&mut self, source: String) {
        self.source = source;
        self.write();
        assert!(matches!(
            self.load(),
            Err(AuthorityError::InvalidConfiguration)
        ));
    }
}

fn parsed<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value
        .parse()
        .unwrap_or_else(|error| panic!("fixture parse: {error:?}"))
}

fn set_mode(path: &std::path::Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("set permissions: {error}"));
}

fn common_config(environment: &str, attestation: &str) -> String {
    format!(
        r#"version = 1
installation_uid = "{INSTALLATION}"
host_identity = "host:runner-01"

[service_limits]
max_connections = 64
max_connections_per_controller = 8
max_frame_bytes = 65536
read_timeout_milliseconds = 1000
write_timeout_milliseconds = 1000

[failed_authentication_rate]
refill_per_minute = 10
burst = 20

[[signing_keys]]
key_id = "key-controller-2026-08"
algorithm = "ed25519"
public_key = "ed25519:{PUBLIC_KEY}"

[[controllers]]
subject = "caller:local-controller"
tenant_ids = ["tenant-acme"]
signing_key_ids = ["key-controller-2026-08"]
profile_uids = ["profile_01ARZ3NDEKTSV4RRFFQ69G5FAV"]
providers = ["codex"]
environments = ["{environment}"]
roles = ["implementer"]
repositories = ["github:acme/payments"]
workspace_ids = ["workspace_01ARZ3NDEKTSV4RRFFQ69G5FAV"]
maximum_ttl_seconds = 900
maximum_session_seconds = 14400
allow_authentication_exception = false
allow_isolation_exception = false

[controllers.capacity]
profile = 2
provider = 3
caller = 4
host = 5

[controllers.rate_limits.acquire]
refill_per_minute = 6
burst = 7

[controllers.rate_limits.readiness]
refill_per_minute = 8
burst = 9

[controllers.rate_limits.principal_mismatch]
refill_per_minute = 10
burst = 11

{attestation}
"#
    )
}

pub(crate) fn valid_macos_config() -> String {
    common_config(
        "local-development",
        r#"[controllers.attestation]
mode = "macos-development-unqualified-v1"
acknowledged = true"#,
    )
}

#[cfg(target_os = "macos")]
fn valid_platform_config(_temporary: &TempDir) -> String {
    valid_macos_config()
}

#[cfg(target_os = "linux")]
fn valid_platform_config(temporary: &TempDir) -> String {
    use sha2::{Digest, Sha256};

    let executable = temporary.path().join("trusted-controller");
    fs::copy(
        std::env::current_exe().unwrap_or_else(|error| panic!("current exe: {error}")),
        &executable,
    )
    .unwrap_or_else(|error| panic!("copy executable: {error}"));
    set_mode(&executable, 0o555);
    let bytes = fs::read(&executable).unwrap_or_else(|error| panic!("read executable: {error}"));
    let digest = format!("sha256:{:x}", Sha256::digest(bytes));
    common_config(
        "production",
        &format!(
            r#"[controllers.attestation]
mode = "linux-peer-v1"
uid = {}
gid = {}
executable = "{}"
executable_sha256 = "{}"
cgroup_v2_path = "/system.slice/controller.service"
systemd_unit = "controller.service""#,
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
            executable.display(),
            digest,
        ),
    )
}

#[test]
fn strict_loader_prepares_redacted_exact_policy() {
    let fixture = Fixture::new();
    let authority = fixture
        .load()
        .unwrap_or_else(|error| panic!("load authority: {error:?}"));
    let rendered = format!("{authority:?} {:?}", authority.redacted_view());
    assert!(!rendered.contains(PUBLIC_KEY));
    assert!(!rendered.contains("trusted-controller"));
    assert_eq!(authority.redacted_view().signing_key_count, 1);

    let controller = &authority.controllers[0];
    let policy = controller
        .exact_policy()
        .unwrap_or_else(|error| panic!("exact policy: {error:?}"));
    assert!(matches!(policy.profile_uids, AllowScope::Only(ref values) if values.len() == 1));
    assert!(
        matches!(policy.providers, AllowScope::Only(ref values) if values == &[Provider::Codex])
    );
    assert!(matches!(policy.environments, AllowScope::Only(ref values) if values.len() == 1));
    assert!(
        matches!(policy.roles, AllowScope::Only(ref values) if values == &[AgentRole::Implementer])
    );
    assert!(
        matches!(policy.caller_subjects, AllowScope::Only(ref values) if values == &[parsed("caller:local-controller")])
    );
    assert!(matches!(policy.repositories, AllowScope::Only(ref values) if values.len() == 1));
    assert_eq!(policy.capacity.profile(), 2);
    assert_eq!(policy.capacity.provider(), 3);
    assert_eq!(policy.capacity.caller(), 4);
    assert_eq!(policy.capacity.host(), 5);
    assert!(!policy.allow_authentication_exception);
    assert!(!policy.allow_isolation_exception);
}

#[test]
fn loader_rejects_unsafe_file_and_directory_modes() {
    for mode in [0o711, 0o755] {
        let fixture = Fixture::new();
        set_mode(&fixture.paths.config_dir, mode);
        assert!(matches!(
            fixture.load(),
            Err(AuthorityError::UnsafeConfiguration)
        ));
    }
    let fixture = Fixture::new();
    set_mode(&fixture.paths.automation_authority_config(), 0o644);
    assert!(matches!(
        fixture.load(),
        Err(AuthorityError::UnsafeConfiguration)
    ));
}

#[test]
fn loader_rejects_symlinks_hardlinks_and_oversize_before_parsing() {
    let fixture = Fixture::new();
    let authority_path = fixture.paths.automation_authority_config();
    let target = fixture.paths.config_dir.join("target.toml");
    fs::rename(&authority_path, &target).unwrap_or_else(|error| panic!("rename: {error}"));
    symlink(&target, &authority_path).unwrap_or_else(|error| panic!("symlink: {error}"));
    assert!(matches!(
        fixture.load(),
        Err(AuthorityError::UnsafeConfiguration)
    ));

    fs::remove_file(&authority_path).unwrap_or_else(|error| panic!("unlink symlink: {error}"));
    fs::hard_link(&target, &authority_path).unwrap_or_else(|error| panic!("hard link: {error}"));
    assert!(matches!(
        fixture.load(),
        Err(AuthorityError::UnsafeConfiguration)
    ));

    fs::remove_file(&authority_path).unwrap_or_else(|error| panic!("unlink hardlink: {error}"));
    fs::remove_file(&target).unwrap_or_else(|error| panic!("unlink target: {error}"));
    fs::write(&authority_path, vec![b'x'; 1_048_577])
        .unwrap_or_else(|error| panic!("oversize fixture: {error}"));
    set_mode(&authority_path, 0o600);
    assert!(matches!(fixture.load(), Err(AuthorityError::TooLarge)));
}

#[test]
fn missing_and_nonregular_authority_files_fail_without_creation_or_blocking() {
    let fixture = Fixture::new();
    let authority_path = fixture.paths.automation_authority_config();
    fs::remove_file(&authority_path).unwrap_or_else(|error| panic!("remove fixture: {error}"));
    assert!(matches!(fixture.load(), Err(AuthorityError::Unavailable)));
    assert!(!authority_path.exists());

    #[cfg(target_os = "linux")]
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &authority_path,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .unwrap_or_else(|error| panic!("fifo fixture: {error}"));
    #[cfg(target_os = "macos")]
    let _socket = std::os::unix::net::UnixListener::bind(&authority_path)
        .unwrap_or_else(|error| panic!("socket fixture: {error}"));
    assert!(matches!(
        fixture.load(),
        Err(AuthorityError::UnsafeConfiguration)
    ));
}

#[test]
fn parse_and_identity_errors_are_value_and_path_free() {
    let mut fixture = Fixture::new();
    let valid_source = fixture.source.clone();
    fixture.source = "canary-secret = [ definitely-not-toml".to_owned();
    fixture.write();
    let error = fixture
        .load()
        .err()
        .unwrap_or_else(|| panic!("invalid config accepted"));
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("canary-secret"));
    assert!(!rendered.contains(&fixture.paths.config_dir.display().to_string()));

    fixture.source = valid_source.replace(INSTALLATION, "installation_01ARZ3NDEKTSV4RRFFQ69G5FAW");
    fixture.write();
    assert!(matches!(
        fixture.load(),
        Err(AuthorityError::InstallationMismatch)
    ));
}

#[test]
fn invalid_scope_key_and_controller_shapes_fail_closed() {
    let base = Fixture::new();
    let cases = [
        base.source
            .replace("tenant_ids = [\"tenant-acme\"]", "tenant_ids = [\"*\"]"),
        base.source.replace(
            "workspace_ids = [\"workspace_01ARZ3NDEKTSV4RRFFQ69G5FAV\"]",
            "workspace_ids = []",
        ),
        base.source.replace(
            "roles = [\"implementer\"]",
            "roles = [\"implementer\", \"implementer\"]",
        ),
        base.source.replace(
            "signing_key_ids = [\"key-controller-2026-08\"]",
            "signing_key_ids = [\"key-missing\"]",
        ),
        base.source.replace(
            "maximum_session_seconds = 14400",
            "maximum_session_seconds = 604801",
        ),
        base.source.replace(PUBLIC_KEY, &"0".repeat(64)),
    ];
    for source in cases {
        let mut fixture = Fixture::new();
        fixture.source = source;
        fixture.write();
        assert!(matches!(
            fixture.load(),
            Err(AuthorityError::InvalidConfiguration)
        ));
    }
}

#[test]
fn every_scope_family_rejects_empty_duplicate_and_wildcard_lists() {
    let mut fixture = Fixture::new();
    let base = fixture.source.clone();
    for (field, item) in [
        ("tenant_ids", "\"tenant-acme\""),
        ("signing_key_ids", "\"key-controller-2026-08\""),
        ("profile_uids", "\"profile_01ARZ3NDEKTSV4RRFFQ69G5FAV\""),
        ("providers", "\"codex\""),
        (
            "environments",
            if cfg!(target_os = "macos") {
                "\"local-development\""
            } else {
                "\"production\""
            },
        ),
        ("roles", "\"implementer\""),
        ("repositories", "\"github:acme/payments\""),
        ("workspace_ids", "\"workspace_01ARZ3NDEKTSV4RRFFQ69G5FAV\""),
    ] {
        let needle = format!("{field} = [{item}]");
        for replacement in [
            format!("{field} = []"),
            format!("{field} = [\"*\"]"),
            format!("{field} = [{item}, {item}]"),
        ] {
            fixture.assert_invalid(base.replacen(&needle, &replacement, 1));
        }
    }
}

#[test]
fn schema_algorithm_and_scalar_bounds_are_strict() {
    let mut fixture = Fixture::new();
    let base = fixture.source.clone();
    let replacements = [
        ("version = 1", "version = 2"),
        ("algorithm = \"ed25519\"", "algorithm = \"rsa\""),
        ("max_connections = 64", "max_connections = 0"),
        ("max_connections = 64", "max_connections = 1025"),
        (
            "max_connections_per_controller = 8",
            "max_connections_per_controller = 0",
        ),
        (
            "max_connections_per_controller = 8",
            "max_connections_per_controller = 65",
        ),
        ("max_frame_bytes = 65536", "max_frame_bytes = 1023"),
        ("max_frame_bytes = 65536", "max_frame_bytes = 1048577"),
        (
            "read_timeout_milliseconds = 1000",
            "read_timeout_milliseconds = 0",
        ),
        (
            "read_timeout_milliseconds = 1000",
            "read_timeout_milliseconds = 30001",
        ),
        (
            "write_timeout_milliseconds = 1000",
            "write_timeout_milliseconds = 0",
        ),
        (
            "write_timeout_milliseconds = 1000",
            "write_timeout_milliseconds = 30001",
        ),
        ("profile = 2", "profile = 0"),
        ("provider = 3", "provider = 1000001"),
        ("caller = 4", "caller = 0"),
        ("host = 5", "host = 1000001"),
        ("maximum_ttl_seconds = 900", "maximum_ttl_seconds = 0"),
        ("maximum_ttl_seconds = 900", "maximum_ttl_seconds = 86401"),
        (
            "maximum_session_seconds = 14400",
            "maximum_session_seconds = 899",
        ),
        (
            "maximum_session_seconds = 14400",
            "maximum_session_seconds = 604801",
        ),
    ];
    for (needle, replacement) in replacements {
        fixture.assert_invalid(base.replacen(needle, replacement, 1));
    }
    for section in [
        "[failed_authentication_rate]",
        "[controllers.rate_limits.acquire]",
        "[controllers.rate_limits.readiness]",
        "[controllers.rate_limits.principal_mismatch]",
    ] {
        let marker = format!("{section}\nrefill_per_minute = ");
        let start = base.find(&marker).unwrap_or_else(|| panic!("rate marker"));
        let suffix = &base[start..];
        let line = suffix.lines().nth(1).unwrap_or_else(|| panic!("rate line"));
        fixture.assert_invalid(base.replacen(line, "refill_per_minute = 0", 1));
    }
    fixture.assert_invalid(format!("{base}\nunknown_canary = true\n"));
    fixture.assert_invalid(format!("version = 1\n{base}"));
    fixture.assert_invalid(base.replace(PUBLIC_KEY, &PUBLIC_KEY.to_ascii_uppercase()));
    fixture.assert_invalid(base.replace(PUBLIC_KEY, "abcd"));
}

#[test]
fn duplicate_subject_key_and_attestation_are_rejected() {
    let base = Fixture::new();
    let controller = base.source[base
        .source
        .find("[[controllers]]")
        .unwrap_or_else(|| panic!("controller marker"))..]
        .to_owned();
    let duplicate_key = format!(
        "{}\n[[signing_keys]]\nkey_id = \"key-controller-2026-08\"\nalgorithm = \"ed25519\"\npublic_key = \"ed25519:{PUBLIC_KEY}\"\n",
        base.source
    );
    let duplicate_subject = format!("{}\n{controller}", base.source);
    let duplicate_attestation = format!(
        "{}\n{}",
        base.source,
        controller.replace("caller:local-controller", "caller:other-controller")
    );
    for source in [duplicate_key, duplicate_subject, duplicate_attestation] {
        let mut fixture = Fixture::new();
        fixture.source = source;
        fixture.write();
        assert!(matches!(
            fixture.load(),
            Err(AuthorityError::InvalidConfiguration)
        ));
    }
}

#[test]
fn unreferenced_signing_key_is_rejected() {
    let mut fixture = Fixture::new();
    write!(
        fixture.source,
        "\n[[signing_keys]]\nkey_id = \"key-unused\"\nalgorithm = \"ed25519\"\npublic_key = \"ed25519:{PUBLIC_KEY}\"\n"
    )
    .unwrap_or_else(|error| panic!("append signing key: {error}"));
    fixture.write();
    assert!(matches!(
        fixture.load(),
        Err(AuthorityError::InvalidConfiguration)
    ));
}

#[test]
fn configuration_digest_binds_exact_validated_bytes() {
    let first = Fixture::new();
    let mut second = Fixture::new();
    second.source.push('\n');
    second.write();
    let first = first
        .load()
        .unwrap_or_else(|error| panic!("first: {error:?}"));
    let second = second
        .load()
        .unwrap_or_else(|error| panic!("second: {error:?}"));
    assert_ne!(first.configuration_digest(), second.configuration_digest());
}

#[cfg(target_os = "macos")]
#[test]
fn linux_attestation_mode_is_unavailable_on_macos() {
    let mut fixture = Fixture::new();
    fixture.source = fixture.source.replace(
        "mode = \"macos-development-unqualified-v1\"\nacknowledged = true",
        "mode = \"linux-peer-v1\"\nuid = 1\ngid = 1\nexecutable = \"/bin/echo\"\nexecutable_sha256 = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\ncgroup_v2_path = \"/system.slice/controller.service\"\nsystemd_unit = \"controller.service\"",
    );
    fixture.write();
    assert!(matches!(
        fixture.load(),
        Err(AuthorityError::InvalidConfiguration)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn macos_attestation_mode_is_unavailable_on_linux() {
    let mut fixture = Fixture::new();
    let start = fixture
        .source
        .find("[controllers.attestation]")
        .unwrap_or_else(|| panic!("attestation marker"));
    fixture.source.truncate(start);
    fixture.source.push_str(
        "[controllers.attestation]\nmode = \"macos-development-unqualified-v1\"\nacknowledged = true\n",
    );
    fixture.write();
    assert!(matches!(
        fixture.load(),
        Err(AuthorityError::InvalidConfiguration)
    ));
}

fn authorization() -> WorkOrderAuthorization {
    WorkOrderAuthorization {
        schema: WorkOrderAuthorizationSchema,
        algorithm: WorkOrderProofAlgorithm::Ed25519,
        key_id: parsed("key-controller-2026-08"),
        client_request_id: parsed("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        tenant_id: parsed("tenant-acme"),
        work_order_id: parsed("wo_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        work_order_digest: parsed(
            "sha256:a36dbc1704725260b0896399529c16a86acabb6849bb1c9abeb251d7ffd16e6c",
        ),
        run_id: parsed("run_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        attempt_id: parsed("attempt_01"),
        role: AgentRole::Implementer,
        provider: Provider::Codex,
        profile_ref: parsed("codex:automation-production"),
        profile_uid: parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        repository: parsed("github:acme/payments"),
        workspace_id: parsed("workspace_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        environment: parsed("production"),
        not_before: parsed("2026-08-21T10:00:00Z"),
        expires_at: parsed("2026-08-21T14:00:00Z"),
        maximum_ttl_seconds: MaximumTtlSeconds::from_seconds(900)
            .unwrap_or_else(|error| panic!("ttl: {error:?}")),
        maximum_session_seconds: DurationSeconds::from_seconds(14_400)
            .unwrap_or_else(|error| panic!("session: {error:?}")),
        signature: DetachedSignature::parse(
            "jLtlv6wVNme_sIhGEIcT25hnhY4YrkAwOolb60L22TWa9DRkudNgfEAxrBSrCm3YXjvFIRsujAKizOeO7wjrAw",
        )
        .unwrap_or_else(|error| panic!("signature: {error:?}")),
    }
}

#[cfg(target_os = "macos")]
fn encode_signature(bytes: &[u8; 64]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(86);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (chunk.get(1).copied().map_or(0, u32::from) << 8)
            | chunk.get(2).copied().map_or(0, u32::from);
        output.push(char::from(ALPHABET[((value >> 18) & 63) as usize]));
        output.push(char::from(ALPHABET[((value >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            output.push(char::from(ALPHABET[((value >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[(value & 63) as usize]));
        }
    }
    output
}

#[test]
fn published_vector_is_strict_and_every_scope_and_ceiling_is_enforced() {
    let fixture = Fixture::new();
    let mut authority = fixture
        .load()
        .unwrap_or_else(|error| panic!("load: {error:?}"));
    authority.controllers[0].environments = [parsed("production")].into_iter().collect();
    let controller = authority.controllers[0].clone();
    let authorization = authorization();
    let now = parsed("2026-08-21T10:00:00Z");
    assert!(
        authority
            .verify_claims(&controller, &authorization, &now)
            .is_ok()
    );

    for invalid_now in ["2026-08-21T09:59:59Z", "2026-08-21T14:00:00Z"] {
        assert!(matches!(
            authority.verify_claims(&controller, &authorization, &parsed(invalid_now)),
            Err(ProofError::WorkOrderProofInvalid)
        ));
    }
    let mut bad_signature = authorization.clone();
    bad_signature.signature =
        DetachedSignature::parse(format!("A{}", &authorization.signature.as_str()[1..]))
            .unwrap_or_else(|error| panic!("signature shape: {error:?}"));
    assert!(matches!(
        authority.verify_claims(&controller, &bad_signature, &now),
        Err(ProofError::WorkOrderProofInvalid)
    ));

    let mut narrowed = Vec::new();
    let mut value = controller.clone();
    value.tenant_ids.clear();
    narrowed.push(value);
    let mut value = controller.clone();
    value.signing_key_ids.clear();
    narrowed.push(value);
    let mut value = controller.clone();
    value.profile_uids.clear();
    narrowed.push(value);
    let mut value = controller.clone();
    value.providers = [Provider::Claude].into_iter().collect();
    narrowed.push(value);
    let mut value = controller.clone();
    value.environments = [parsed("staging")].into_iter().collect();
    narrowed.push(value);
    let mut value = controller.clone();
    value.roles = vec![AgentRole::PrReviewer];
    narrowed.push(value);
    let mut value = controller.clone();
    value.repositories = [parsed("github:other/repository")].into_iter().collect();
    narrowed.push(value);
    let mut value = controller.clone();
    value.workspace_ids = [parsed("workspace_other")].into_iter().collect();
    narrowed.push(value);
    let mut value = controller.clone();
    value.maximum_ttl_seconds = 899;
    narrowed.push(value);
    let mut value = controller;
    value.maximum_session_seconds = 14_399;
    narrowed.push(value);
    assert!(narrowed.iter().all(|controller| {
        matches!(
            authority.verify_claims(controller, &authorization, &now),
            Err(ProofError::WorkOrderProofInvalid)
        )
    }));
}

#[test]
fn proof_failures_do_not_echo_key_or_signature_material() {
    let fixture = Fixture::new();
    let mut authority = fixture
        .load()
        .unwrap_or_else(|error| panic!("load: {error:?}"));
    authority.controllers[0].environments = [parsed("production")].into_iter().collect();
    let mut authorization = authorization();
    authorization.key_id = parsed("key-canary-secret");
    let error = authority
        .verify_claims(
            &authority.controllers[0],
            &authorization,
            &parsed("2026-08-21T10:00:00Z"),
        )
        .err()
        .unwrap_or_else(|| panic!("unknown key accepted"));
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("key-canary-secret"));
    assert!(!rendered.contains(authorization.signature.as_str()));
}

#[cfg(target_os = "macos")]
#[test]
fn verified_token_is_time_caller_and_configuration_bound() {
    use crate::automation::attestation::MacosDevelopmentAttestor;

    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let mut public_key = String::new();
    for byte in signing_key.verifying_key().as_bytes() {
        write!(public_key, "{byte:02x}")
            .unwrap_or_else(|error| panic!("encode public key: {error}"));
    }
    let mut fixture = Fixture::new();
    fixture.source = fixture.source.replace(PUBLIC_KEY, &public_key);
    fixture.write();
    let authority = fixture
        .load()
        .unwrap_or_else(|error| panic!("load: {error:?}"));
    let caller = MacosDevelopmentAttestor::new(true)
        .attest(&authority)
        .unwrap_or_else(|error| panic!("attest: {error:?}"));
    let mut authorization = authorization();
    authorization.environment = parsed("local-development");
    let message = authorization
        .signature_message()
        .unwrap_or_else(|error| panic!("message: {error:?}"));
    authorization.signature =
        DetachedSignature::parse(encode_signature(&signing_key.sign(&message).to_bytes()))
            .unwrap_or_else(|error| panic!("signed fixture: {error:?}"));
    let now = parsed("2026-08-21T10:00:00Z");
    let proof = authority
        .verify_work_order(&caller, &authorization, &now)
        .unwrap_or_else(|error| panic!("verify: {error:?}"));
    assert!(proof.matches(&authority, &caller, &authorization, &now));
    assert!(!proof.matches(
        &authority,
        &caller,
        &authorization,
        &parsed("2026-08-21T14:00:00Z")
    ));
    let mut changed = authorization.clone();
    changed.tenant_id = parsed("tenant-other");
    assert!(!proof.matches(&authority, &caller, &changed, &now));
    assert_eq!(proof.authorization(), &authorization);
    assert_eq!(proof.caller_subject(), caller.subject());
    assert_eq!(proof.host_identity(), caller.host_identity());
    assert_eq!(proof.assurance(), caller.assurance());
    assert_eq!(proof.key_id(), &authorization.key_id);
    assert_eq!(
        proof.signed_message_digest(),
        Sha256Digest::hash(
            authorization
                .signature_message()
                .unwrap_or_else(|error| panic!("message: {error:?}"))
        )
    );
    assert!(!format!("{proof:?}").contains(authorization.signature.as_str()));

    let mut changed_fixture = Fixture::new();
    changed_fixture.source.push('\n');
    changed_fixture.write();
    let changed_authority = changed_fixture
        .load()
        .unwrap_or_else(|error| panic!("changed load: {error:?}"));
    assert!(!proof.matches(&changed_authority, &caller, &authorization, &now));
}
