use std::{
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    sync::mpsc::{self, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use secrecy::{ExposeSecret, SecretString};
use toml_edit::{DocumentMut, Item, Table, value};

use crate::{
    Error, Result,
    binary::{ExternalProgram, resolve_external_binary, sanitize_search_path},
    brand::is_wrapper_environment_key,
    config::{
        AppPaths, MetadataStore, ProfileLockGuard, acquire_profile_lock, ensure_secure_directory,
        validate_sensitive_file, write_secure_text,
    },
    model::{ClaudeAuth, CodexAuth, Config, Profile, ProfileId, Provider},
    secret::{SecretProvider, parse_profile_secret_ref, write_secret_to_stdin},
};

pub const BLOCKED_ENVIRONMENT: &[&str] = &[
    "CLAUDECODE",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_PROFILE",
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_ORGANIZATION_ID",
    "ANTHROPIC_SERVICE_ACCOUNT_ID",
    "ANTHROPIC_WORKSPACE_ID",
    "ANTHROPIC_IDENTITY_TOKEN_FILE",
    "ANTHROPIC_IDENTITY_TOKEN",
    "ANTHROPIC_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_OAUTH_SCOPES",
    "CLAUDE_ENV_FILE",
    "CLAUDE_CODE_SHELL_PREFIX",
    "CLAUDE_CODE_SHELL",
    "CLAUDE_CODE_GIT_BASH_PATH",
    "CLAUDE_CODE_PLUGIN_SEED_DIR",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
    "CLAUDE_CODE_SKIP_VERTEX_AUTH",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT_ID",
    "OPENAI_BASE_URL",
    "CODEX_ACCESS_TOKEN",
    "CODEX_API_KEY",
    "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
    "CODEX_REVOKE_TOKEN_URL_OVERRIDE",
    "CODEX_HOME",
    // Process-loader, interpreter, proxy, and trust-store controls can execute
    // code before the verified vendor entry point or reroute its TLS traffic.
    "BASH_ENV",
    "ENV",
    "SHELL",
    "ZDOTDIR",
    "GIT_SSH_COMMAND",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "NPM_CONFIG_NODE_OPTIONS",
    "BUN_OPTIONS",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5OPT",
    "PERL5LIB",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "CLASSPATH",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
];

const BLOCKED_ENVIRONMENT_PREFIXES: &[&str] = &["DYLD_", "LD_"];
const BLOCKED_VENDOR_ENVIRONMENT_PREFIXES: &[&str] =
    &["ANTHROPIC_", "CLAUDE_", "OPENAI_", "CODEX_"];

const CLAUDE_SETTINGS_CREDENTIAL_KEYS: &[&str] = &[
    "apiKeyHelper",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_PROFILE",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_ORGANIZATION_ID",
    "ANTHROPIC_SERVICE_ACCOUNT_ID",
    "ANTHROPIC_WORKSPACE_ID",
    "ANTHROPIC_IDENTITY_TOKEN_FILE",
    "ANTHROPIC_IDENTITY_TOKEN",
    "ANTHROPIC_OAUTH_TOKEN",
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_OAUTH_SCOPES",
];

const UNTRUSTED_COMMAND_KEYS: &[&str] = &[
    "hooks",
    "mcpServers",
    "mcp_servers",
    "notify",
    "model_providers",
];

const UNTRUSTED_CLAUDE_PLUGIN_KEYS: &[&str] = &["enabledPlugins", "extraKnownMarketplaces"];

const UNTRUSTED_CLAUDE_EXECUTABLE_KEYS: &[&str] = &[
    "statusLine",
    "subagentStatusLine",
    "fileSuggestion",
    "otelHeadersHelper",
];

const UNTRUSTED_CODEX_EXTENSION_KEYS: &[&str] = &[
    "shell_environment_policy",
    "agents",
    "skills",
    "plugins",
    "marketplaces",
    "apps",
    "tool_suggest",
    "features",
    "sqlite_home",
    "log_dir",
    "model_catalog_json",
    "model_instructions_file",
    "experimental_compact_prompt_file",
    "forced_chatgpt_workspace_id",
    "forced_login_method",
    "cli_auth_credentials_store",
];

const CODEX_ROUTING_KEYS: &[&str] = &[
    "base_url",
    "openai_base_url",
    "chatgpt_base_url",
    "experimental_bearer_token",
    "bearer_token_env_var",
    "env_key",
    "env_http_headers",
    "http_headers",
    "query_params",
    "model_providers",
];

const MAX_VERSION_OUTPUT_BYTES: usize = 64 * 1024;
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PROJECT_DEFINITION_BYTES: u64 = 1024 * 1024;
const MAX_PROJECT_DEFINITION_ENTRIES: usize = 1024;
const MAX_PROJECT_DEFINITION_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialState {
    Available,
    Unavailable,
    Unverified,
}

impl CredentialState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Unverified => "unverified",
        }
    }
}

pub fn build_environment<I, K, V>(
    profile: &Profile,
    secret: Option<&str>,
    base: I,
) -> Result<BTreeMap<OsString, OsString>>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<OsString>,
    V: Into<OsString>,
{
    let mut output = sanitized_inherited_environment(base)?;
    apply_profile_environment(profile, secret, &mut output)?;
    Ok(output)
}

pub(crate) fn sanitized_inherited_environment<I, K, V>(
    base: I,
) -> Result<BTreeMap<OsString, OsString>>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<OsString>,
    V: Into<OsString>,
{
    let mut output = BTreeMap::new();
    for (key, value) in base {
        let key = key.into();
        if is_blocked_key(&key) {
            continue;
        }
        let value = value.into();
        if key.to_string_lossy().eq_ignore_ascii_case("PATH") {
            if let Some(path) = sanitize_search_path(&value)? {
                output.insert(key, path);
            }
        } else {
            output.insert(key, value);
        }
    }
    Ok(output)
}

fn apply_profile_environment(
    profile: &Profile,
    secret: Option<&str>,
    output: &mut BTreeMap<OsString, OsString>,
) -> Result<()> {
    match profile {
        Profile::Claude {
            auth,
            state_dir,
            wif,
            ..
        } => {
            output.insert("CLAUDE_CONFIG_DIR".into(), state_dir.as_os_str().to_owned());
            output.insert("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB".into(), "1".into());
            match auth {
                ClaudeAuth::SubscriptionToken => {
                    let secret = require_secret(secret, "Claude subscription token")?;
                    output.insert("CLAUDE_CODE_OAUTH_TOKEN".into(), secret.into());
                }
                ClaudeAuth::ApiKey => {
                    let secret = require_secret(secret, "Anthropic API key")?;
                    output.insert("ANTHROPIC_API_KEY".into(), secret.into());
                }
                ClaudeAuth::Wif => {
                    let wif = wif.as_ref().ok_or_else(|| {
                        Error::InvalidConfig("Claude WIF profile is missing metadata".to_owned())
                    })?;
                    output.insert(
                        "ANTHROPIC_ORGANIZATION_ID".into(),
                        wif.organization_id.clone().into(),
                    );
                    output.insert(
                        "ANTHROPIC_FEDERATION_RULE_ID".into(),
                        wif.federation_rule_id.clone().into(),
                    );
                    output.insert(
                        "ANTHROPIC_SERVICE_ACCOUNT_ID".into(),
                        wif.service_account_id.clone().into(),
                    );
                    output.insert(
                        "ANTHROPIC_IDENTITY_TOKEN_FILE".into(),
                        wif.identity_token_file.as_os_str().to_owned(),
                    );
                    if let Some(workspace) = &wif.workspace_id {
                        output.insert("ANTHROPIC_WORKSPACE_ID".into(), workspace.clone().into());
                    }
                }
            }
        }
        Profile::Codex { state_dir, .. } => {
            output.insert("CODEX_HOME".into(), state_dir.as_os_str().to_owned());
        }
    }

    Ok(())
}

pub fn run_profile(
    config: &Config,
    paths: &AppPaths,
    profile_id: &ProfileId,
    profile: &Profile,
    args: &[OsString],
    secrets: &dyn SecretProvider,
    options: &RunOptions,
) -> Result<i32> {
    let exclusive_run_lock = matches!(
        profile,
        Profile::Codex {
            auth: CodexAuth::ChatgptOauth | CodexAuth::ApiKey | CodexAuth::AccessToken,
            ..
        }
    );
    let lifecycle = acquire_profile_lock(
        &paths.profile_lock(profile.provider(), profile_id.name()),
        exclusive_run_lock,
    )?;
    ensure_profile_is_current(paths, profile_id, profile)?;
    ensure_secure_directory(profile.state_dir())?;
    let program = resolve_vendor_binary(config, profile.provider())?;

    match profile {
        Profile::Claude {
            auth: ClaudeAuth::Wif,
            wif,
            ..
        } => {
            let token_file = &wif
                .as_ref()
                .ok_or_else(|| Error::InvalidConfig("missing WIF metadata".to_owned()))?
                .identity_token_file;
            validate_sensitive_file(token_file)?;
        }
        Profile::Claude { .. } => {}
        Profile::Codex { .. } => {
            validate_codex_settings(profile.state_dir(), &options.cwd)?;
            ensure_codex_config(paths, profile_id, profile, &lifecycle)?;
        }
    }

    if profile.provider() == Provider::Claude {
        validate_claude_settings(profile.state_dir(), &options.cwd)?;
    }
    validate_forwarded_args(profile, args)?;
    enforce_runner_policy(profile, options.non_interactive, options.trusted_runner)?;

    if matches!(
        profile,
        Profile::Codex {
            auth: CodexAuth::ChatgptOauth,
            ..
        }
    ) && options.non_interactive
    {
        codex_login_status(config, paths, profile_id, profile, &lifecycle)?;
    }

    let secret = if profile.requires_static_secret() {
        let reference = parse_profile_secret_ref(profile_id, profile.secret_ref())?;
        Some(secrets.get(&reference, options.non_interactive)?)
    } else {
        None
    };

    if let Profile::Codex {
        auth: auth @ (CodexAuth::ApiKey | CodexAuth::AccessToken),
        ..
    } = profile
    {
        let selected = secret.as_ref().ok_or_else(|| {
            Error::InvalidConfig("Codex static profile resolved no credential".to_owned())
        })?;
        let login_flag = match auth {
            CodexAuth::ApiKey => "--with-api-key",
            CodexAuth::AccessToken => "--with-access-token",
            CodexAuth::ChatgptOauth => unreachable!("matched only static Codex auth modes"),
        };
        let login_code = codex_static_login(
            config, paths, profile_id, profile, selected, login_flag, &lifecycle,
        )?;
        if login_code != 0 {
            return Ok(login_code);
        }
    }

    if let Profile::Claude {
        auth: auth @ (ClaudeAuth::SubscriptionToken | ClaudeAuth::ApiKey),
        ..
    } = profile
    {
        let selected = secret.as_ref().ok_or_else(|| {
            Error::InvalidConfig("Claude static profile resolved no credential".to_owned())
        })?;
        validate_claude_local_auth_route(config, profile_id, profile, *auth, selected, &lifecycle)?;
    }

    let environment = build_environment(
        profile,
        secret.as_ref().map(ExposeSecret::expose_secret),
        env::vars_os(),
    )?;
    // Claude's child environment owns its selected static credential. Codex
    // static credentials were delivered to the isolated vendor cache through
    // official stdin login and are deliberately absent from the main child.
    // In either case, do not retain the resolved secret copy while waiting.
    drop(secret);
    let result = spawn_inherited(&program, args, environment)?;
    Ok(result)
}

#[derive(Clone, Debug)]
pub struct RunOptions {
    pub cwd: PathBuf,
    pub non_interactive: bool,
    pub trusted_runner: bool,
}

fn ensure_profile_is_current(
    paths: &AppPaths,
    profile_id: &ProfileId,
    expected: &Profile,
) -> Result<()> {
    let current = MetadataStore::new(paths.clone()).load_config()?;
    let profile = current
        .profiles
        .get(profile_id)
        .ok_or_else(|| Error::ProfileNotFound(profile_id.to_string()))?;
    if profile != expected {
        return Err(Error::InvalidInput(format!(
            "profile `{profile_id}` changed before the operation acquired its lifecycle lock; retry"
        )));
    }
    Ok(())
}

pub(crate) fn login_codex(
    config: &Config,
    paths: &AppPaths,
    profile_id: &ProfileId,
    profile: &Profile,
    device: bool,
    lifecycle: &ProfileLockGuard,
) -> Result<i32> {
    validate_current_codex_settings(profile)?;
    ensure_codex_config(paths, profile_id, profile, lifecycle)?;
    let program = resolve_vendor_binary(config, Provider::Codex)?;
    let environment = build_environment(profile, None, env::vars_os())?;
    let mut args = vec![OsString::from("login")];
    if device {
        args.push(OsString::from("--device-auth"));
    }
    spawn_inherited(&program, &args, environment)
}

pub(crate) fn codex_static_login(
    config: &Config,
    paths: &AppPaths,
    profile_id: &ProfileId,
    profile: &Profile,
    secret: &SecretString,
    login_flag: &str,
    lifecycle: &ProfileLockGuard,
) -> Result<i32> {
    validate_current_codex_settings(profile)?;
    ensure_codex_config(paths, profile_id, profile, lifecycle)?;
    let program = resolve_vendor_binary(config, Provider::Codex)?;
    let environment = build_environment(profile, None, env::vars_os())?;
    let mut command = Command::new(&program);
    let signal_forwarder = SignalForwarder::new().map_err(|source| Error::Spawn {
        program: program.display().to_string(),
        source,
    })?;
    command
        .arg("login")
        .arg(login_flag)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|source| Error::Spawn {
        program: program.display().to_string(),
        source,
    })?;
    drop(command);
    let Some(mut stdin) = child.stdin.take() else {
        terminate_and_reap(&mut child);
        return Err(Error::CredentialPipe {
            program: program.display().to_string(),
        });
    };
    if let Err(error) = write_secret_to_stdin(&mut stdin, secret, &program.display().to_string()) {
        drop(stdin);
        terminate_and_reap(&mut child);
        return Err(error);
    }
    drop(stdin);
    let status = match signal_forwarder.wait(&mut child) {
        Ok(status) => status,
        Err(source) => {
            terminate_and_reap(&mut child);
            return Err(Error::Spawn {
                program: program.display().to_string(),
                source,
            });
        }
    };
    Ok(status_code(status))
}

fn terminate_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_for_preflight(
    child: &mut Child,
    program: &Path,
    operation: &str,
    timeout: Duration,
) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                terminate_and_reap(child);
                return Err(Error::VendorIncompatible(format!(
                    "{} {operation} exceeded the {timeout:?} preflight limit",
                    program.display(),
                )));
            }
            Err(source) => {
                terminate_and_reap(child);
                return Err(Error::Spawn {
                    program: program.display().to_string(),
                    source,
                });
            }
        }
    }
}

fn capture_preflight_stdout(
    child: &mut Child,
    stdout: ChildStdout,
    program: &Path,
    operation: &str,
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>)> {
    let (sender, receiver) = mpsc::sync_channel(1);
    if let Err(source) = thread::Builder::new()
        .name("ctxlane-preflight-output".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take((MAX_VERSION_OUTPUT_BYTES + 1) as u64)
                .read_to_end(&mut bytes);
            let _ = sender.send((result, bytes));
        })
    {
        terminate_and_reap(child);
        return Err(Error::Spawn {
            program: program.display().to_string(),
            source,
        });
    }

    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut output = None;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(completed)) => status = Some(completed),
                Ok(None) => {}
                Err(source) => {
                    terminate_and_reap(child);
                    return Err(Error::Spawn {
                        program: program.display().to_string(),
                        source,
                    });
                }
            }
        }

        if output.is_none() {
            match receiver.try_recv() {
                Ok((read_result, bytes)) => {
                    if let Err(source) = read_result {
                        if status.is_none() {
                            terminate_and_reap(child);
                        }
                        return Err(Error::Spawn {
                            program: program.display().to_string(),
                            source,
                        });
                    }
                    if bytes.len() > MAX_VERSION_OUTPUT_BYTES {
                        if status.is_none() {
                            terminate_and_reap(child);
                        }
                        return Err(Error::VendorIncompatible(format!(
                            "{} {operation} exceeded the 64 KiB output limit",
                            program.display()
                        )));
                    }
                    output = Some(bytes);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    if status.is_none() {
                        terminate_and_reap(child);
                    }
                    return Err(Error::VendorIncompatible(format!(
                        "{} {operation} output reader failed",
                        program.display()
                    )));
                }
            }
        }

        if let Some(completed) = status
            && let Some(bytes) = output.take()
        {
            return Ok((completed, bytes));
        }

        if Instant::now() >= deadline {
            if status.is_none() {
                terminate_and_reap(child);
            }
            return Err(Error::VendorIncompatible(format!(
                "{} {operation} exceeded the {timeout:?} preflight limit",
                program.display(),
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn logout_codex(
    config: &Config,
    paths: &AppPaths,
    profile_id: &ProfileId,
    profile: &Profile,
    lifecycle: &ProfileLockGuard,
) -> Result<i32> {
    validate_current_codex_settings(profile)?;
    ensure_codex_config(paths, profile_id, profile, lifecycle)?;
    let program = resolve_vendor_binary(config, Provider::Codex)?;
    let environment = build_environment(profile, None, env::vars_os())?;
    spawn_inherited(&program, &[OsString::from("logout")], environment)
}

pub(crate) fn generate_claude_setup_token(
    config: &Config,
    profile: &Profile,
    _lifecycle: &ProfileLockGuard,
) -> Result<i32> {
    validate_current_claude_settings(profile)?;
    let program = resolve_vendor_binary(config, Provider::Claude)?;
    let environment = build_environment_without_selected_secret(profile)?;
    spawn_inherited(&program, &[OsString::from("setup-token")], environment)
}

pub fn credential_state(
    config: &Config,
    paths: &AppPaths,
    profile_id: &ProfileId,
    profile: &Profile,
    secrets: &dyn SecretProvider,
    non_interactive: bool,
) -> Result<CredentialState> {
    let lifecycle = acquire_profile_lock(
        &paths.profile_lock(profile.provider(), profile_id.name()),
        false,
    )?;
    ensure_profile_is_current(paths, profile_id, profile)?;
    enforce_pull_request_static_secret_policy(profile)?;
    match profile {
        Profile::Claude {
            auth: ClaudeAuth::Wif,
            wif,
            ..
        } => {
            let path = &wif
                .as_ref()
                .ok_or_else(|| Error::InvalidConfig("missing WIF metadata".to_owned()))?
                .identity_token_file;
            if !path.exists() {
                return Ok(CredentialState::Unavailable);
            }
            validate_sensitive_file(path)?;
            Ok(CredentialState::Available)
        }
        Profile::Claude {
            auth: auth @ (ClaudeAuth::SubscriptionToken | ClaudeAuth::ApiKey),
            ..
        } => {
            let reference = parse_profile_secret_ref(profile_id, profile.secret_ref())?;
            let secret = match secrets.get(&reference, non_interactive) {
                Ok(secret) => secret,
                Err(Error::CredentialUnavailable { .. }) => {
                    return Ok(CredentialState::Unavailable);
                }
                Err(error) => return Err(error),
            };
            let status = validate_claude_local_auth_route(
                config, profile_id, profile, *auth, &secret, &lifecycle,
            );
            drop(secret);
            status?;
            // Claude derives this status from the selected local environment
            // route. A successful response proves that the CLI recognized the
            // intended auth method, but it does not prove that Anthropic will
            // accept the credential.
            Ok(CredentialState::Unverified)
        }
        Profile::Codex {
            auth: CodexAuth::ApiKey,
            ..
        } => {
            let reference = parse_profile_secret_ref(profile_id, profile.secret_ref())?;
            Ok(if secrets.exists_compatible(&reference, non_interactive)? {
                CredentialState::Available
            } else {
                CredentialState::Unavailable
            })
        }
        Profile::Codex {
            auth: CodexAuth::AccessToken,
            ..
        } => {
            validate_current_codex_settings(profile)?;
            let reference = parse_profile_secret_ref(profile_id, profile.secret_ref())?;
            if !secrets.exists_compatible(&reference, non_interactive)? {
                return Ok(CredentialState::Unavailable);
            }
            match codex_login_status(config, paths, profile_id, profile, &lifecycle) {
                Ok(()) => Ok(CredentialState::Available),
                Err(Error::CredentialUnavailable { .. }) => Ok(CredentialState::Unverified),
                Err(error) => Err(error),
            }
        }
        Profile::Codex {
            auth: CodexAuth::ChatgptOauth,
            expected_workspace_id,
            ..
        } => {
            validate_current_codex_settings(profile)?;
            match codex_login_status(config, paths, profile_id, profile, &lifecycle) {
                Ok(()) if expected_workspace_id.is_some() => Ok(CredentialState::Available),
                Ok(()) => Ok(CredentialState::Unverified),
                Err(Error::CredentialUnavailable { .. }) => Ok(CredentialState::Unavailable),
                Err(error) => Err(error),
            }
        }
    }
}

trait SecretProviderExt {
    fn exists_compatible(
        &self,
        reference: &crate::secret::SecretRef,
        non_interactive: bool,
    ) -> Result<bool>;
}

impl<T: SecretProvider + ?Sized> SecretProviderExt for T {
    fn exists_compatible(
        &self,
        reference: &crate::secret::SecretRef,
        non_interactive: bool,
    ) -> Result<bool> {
        match self.get(reference, non_interactive) {
            Ok(secret) => {
                drop(secret);
                Ok(true)
            }
            Err(Error::CredentialUnavailable { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

pub fn vendor_version(config: &Config, provider: Provider) -> Result<String> {
    let program = resolve_vendor_binary(config, provider)?;
    let mut command = Command::new(&program);
    command
        .arg("--version")
        .env_clear()
        .envs(sanitized_inherited_environment(env::vars_os())?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|source| Error::Spawn {
        program: program.display().to_string(),
        source,
    })?;
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        return Err(Error::CredentialPipe {
            program: program.display().to_string(),
        });
    };
    let (status, bytes) =
        capture_preflight_stdout(&mut child, stdout, &program, "--version", PREFLIGHT_TIMEOUT)?;
    if !status.success() {
        return Err(Error::VendorIncompatible(format!(
            "{} --version exited with {}",
            program.display(),
            status
        )));
    }
    let output = String::from_utf8(bytes).map_err(|_| {
        Error::VendorIncompatible(format!(
            "{} --version returned non-UTF-8 output",
            program.display()
        ))
    })?;
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| {
            Error::VendorIncompatible(format!(
                "{} --version returned no version text",
                program.display()
            ))
        })?
        .to_owned();
    if line.chars().any(char::is_control) {
        return Err(Error::VendorIncompatible(format!(
            "{} --version returned terminal control characters",
            program.display()
        )));
    }
    Ok(line)
}

pub fn resolve_vendor_binary(config: &Config, provider: Provider) -> Result<PathBuf> {
    let (program, configured) = match provider {
        Provider::Claude => (ExternalProgram::Claude, &config.binaries.claude),
        Provider::Codex => (ExternalProgram::Codex, &config.binaries.codex),
    };
    resolve_external_binary(configured, program)
}

fn ensure_codex_config(
    _paths: &AppPaths,
    _profile_id: &ProfileId,
    profile: &Profile,
    _lifecycle: &ProfileLockGuard,
) -> Result<()> {
    let Profile::Codex {
        auth,
        state_dir,
        expected_workspace_id,
        credential_store,
        ..
    } = profile
    else {
        return Err(Error::InvalidInput(
            "Codex configuration requested for a Claude profile".to_owned(),
        ));
    };
    ensure_secure_directory(state_dir)?;
    let config_path = state_dir.join("config.toml");
    let text = if config_path.exists() {
        validate_sensitive_file(&config_path)?;
        fs::read_to_string(&config_path).map_err(|source| Error::ReadFile {
            path: config_path.clone(),
            source,
        })?
    } else {
        String::new()
    };
    let mut document = if text.trim().is_empty() {
        DocumentMut::new()
    } else {
        text.parse::<DocumentMut>().map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to parse vendor config {}: {error}",
                config_path.display()
            ))
        })?
    };
    if let Some(setting) = unsafe_codex_setting(&document.to_string(), false)? {
        return Err(Error::PolicyRefused(format!(
            "Codex profile config {} contains unsupported credential or endpoint routing key `{setting}`",
            config_path.display()
        )));
    }
    let forced_login = match auth {
        CodexAuth::ApiKey => "api",
        CodexAuth::ChatgptOauth | CodexAuth::AccessToken => "chatgpt",
    };
    document["forced_login_method"] = value(forced_login);
    document["cli_auth_credentials_store"] = value(credential_store.to_string());
    if let Some(workspace) = expected_workspace_id {
        document["forced_chatgpt_workspace_id"] = value(workspace.clone());
    } else {
        document.remove("forced_chatgpt_workspace_id");
    }
    let mut shell_environment_policy = Table::new();
    shell_environment_policy["inherit"] = value("core");
    shell_environment_policy["ignore_default_excludes"] = value(false);
    document["shell_environment_policy"] = Item::Table(shell_environment_policy);
    write_secure_text(&config_path, &document.to_string())
}

fn codex_login_status(
    config: &Config,
    paths: &AppPaths,
    profile_id: &ProfileId,
    profile: &Profile,
    lifecycle: &ProfileLockGuard,
) -> Result<()> {
    validate_current_codex_settings(profile)?;
    ensure_codex_config(paths, profile_id, profile, lifecycle)?;
    let program = resolve_vendor_binary(config, Provider::Codex)?;
    let environment = build_environment(profile, None, env::vars_os())?;
    let mut command = Command::new(&program);
    command
        .arg("login")
        .arg("status")
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|source| Error::Spawn {
        program: program.display().to_string(),
        source,
    })?;
    drop(command);
    let status = wait_for_preflight(&mut child, &program, "login status", PREFLIGHT_TIMEOUT)?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::CredentialUnavailable {
            profile: profile_id.to_string(),
            reason: "`codex login status` reported no usable login".to_owned(),
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeAuthStatus {
    logged_in: bool,
    auth_method: String,
    api_provider: String,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    org_name: Option<String>,
}

fn validate_claude_local_auth_route(
    config: &Config,
    profile_id: &ProfileId,
    profile: &Profile,
    auth: ClaudeAuth,
    secret: &SecretString,
    _lifecycle: &ProfileLockGuard,
) -> Result<()> {
    ensure_secure_directory(profile.state_dir())?;
    validate_current_claude_settings(profile)?;
    let program = resolve_vendor_binary(config, Provider::Claude)?;
    let environment = build_environment(profile, Some(secret.expose_secret()), env::vars_os())?;
    let expected_method = match auth {
        ClaudeAuth::SubscriptionToken => "oauth_token",
        ClaudeAuth::ApiKey => "api_key",
        ClaudeAuth::Wif => {
            return Err(Error::InvalidConfig(
                "Claude WIF does not use a static credential status check".to_owned(),
            ));
        }
    };
    let mut command = Command::new(&program);
    command
        .arg("auth")
        .arg("status")
        .arg("--json")
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|source| Error::Spawn {
        program: program.display().to_string(),
        source,
    })?;
    // Drop the command builder immediately; it retains the selected secret in
    // its private environment until the child has been spawned.
    drop(command);
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        return Err(Error::CredentialPipe {
            program: program.display().to_string(),
        });
    };
    let (status, bytes) = capture_preflight_stdout(
        &mut child,
        stdout,
        &program,
        "auth status",
        PREFLIGHT_TIMEOUT,
    )?;
    if !status.success() {
        return Err(Error::IdentityMismatch(format!(
            "`claude auth status --json` could not confirm {profile_id}"
        )));
    }
    let status: ClaudeAuthStatus = serde_json::from_slice(&bytes).map_err(|error| {
        Error::VendorIncompatible(format!(
            "{} auth status returned invalid JSON: {error}",
            program.display()
        ))
    })?;
    if !status.logged_in
        || status.auth_method != expected_method
        || status.api_provider != "firstParty"
    {
        return Err(Error::IdentityMismatch(format!(
            "`claude auth status --json` did not confirm the selected {expected_method} first-party authentication method for {profile_id}"
        )));
    }
    if let Some(expected) = profile.expected_organization() {
        let organization_matches = status
            .org_id
            .as_deref()
            .into_iter()
            .chain(status.org_name.as_deref())
            .any(|actual| actual == expected);
        if !organization_matches {
            return Err(Error::IdentityMismatch(format!(
                "`claude auth status --json` did not expose an organization matching the configured pin for {profile_id}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_claude_settings(state_dir: &Path, cwd: &Path) -> Result<()> {
    let mut candidates = vec![
        (state_dir.join("settings.json"), false),
        (state_dir.join("settings.local.json"), false),
    ];
    for ancestor in project_ancestors(cwd) {
        validate_claude_project_definitions(ancestor)?;
        candidates.push((ancestor.join(".claude/settings.json"), true));
        candidates.push((ancestor.join(".claude/settings.local.json"), true));
        candidates.push((ancestor.join(".mcp.json"), true));
    }

    for (path, untrusted) in candidates {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(Error::ReadFile {
                    path: path.clone(),
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::PolicyRefused(format!(
                "refusing uninspectable Claude settings path {}",
                path.display()
            )));
        }
        if metadata.len() > 1024 * 1024 {
            return Err(Error::PolicyRefused(format!(
                "Claude settings file {} exceeds the 1 MiB inspection limit",
                path.display()
            )));
        }
        let bytes = fs::read(&path).map_err(|source| Error::ReadFile {
            path: path.clone(),
            source,
        })?;
        let document: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::PolicyRefused(format!(
                "cannot inspect invalid Claude settings file {}: {error}",
                path.display()
            ))
        })?;
        if contains_competing_claude_setting(&document, untrusted) {
            return Err(Error::PolicyRefused(format!(
                "Claude settings file {} contains a credential helper, credential, endpoint override, repository command hook, or plugin/marketplace loader that could defeat or exfiltrate the selected profile",
                path.display()
            )));
        }
    }
    Ok(())
}

fn contains_competing_claude_setting(value: &serde_json::Value, untrusted: bool) -> bool {
    match value {
        serde_json::Value::Object(object) => object.iter().any(|(key, child)| {
            CLAUDE_SETTINGS_CREDENTIAL_KEYS
                .iter()
                .any(|blocked| key.eq_ignore_ascii_case(blocked))
                || is_vendor_environment_key(key)
                || (untrusted
                    && (UNTRUSTED_COMMAND_KEYS
                        .iter()
                        .any(|blocked| key.eq_ignore_ascii_case(blocked))
                        || UNTRUSTED_CLAUDE_PLUGIN_KEYS
                            .iter()
                            .any(|blocked| key.eq_ignore_ascii_case(blocked))
                        || UNTRUSTED_CLAUDE_EXECUTABLE_KEYS
                            .iter()
                            .any(|blocked| key.eq_ignore_ascii_case(blocked))
                        || key.eq_ignore_ascii_case("env")))
                || contains_competing_claude_setting(child, untrusted)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| contains_competing_claude_setting(value, untrusted)),
        _ => false,
    }
}

fn validate_claude_project_definitions(project_root: &Path) -> Result<()> {
    let plugin_manifest = project_root.join(".claude-plugin/plugin.json");
    match fs::symlink_metadata(&plugin_manifest) {
        Ok(_) => {
            return Err(Error::PolicyRefused(format!(
                "Claude project plugin manifest {} is not allowed in a wrapped run",
                plugin_manifest.display()
            )));
        }
        Err(source) if source.kind() == ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::ReadFile {
                path: plugin_manifest,
                source,
            });
        }
    }

    for (directory, all_markdown, require_frontmatter) in [
        (project_root.join(".claude/agents"), true, true),
        (project_root.join(".claude/skills"), false, true),
        (project_root.join(".claude/commands"), true, false),
    ] {
        let mut entries = 0;
        inspect_claude_definition_tree(
            &directory,
            0,
            &mut entries,
            all_markdown,
            require_frontmatter,
        )?;
    }
    Ok(())
}

fn inspect_claude_definition_tree(
    path: &Path,
    depth: usize,
    entries: &mut usize,
    all_markdown: bool,
    require_frontmatter: bool,
) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(Error::ReadFile {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(Error::PolicyRefused(format!(
            "refusing symlinked Claude project definition path {}",
            path.display()
        )));
    }
    if metadata.is_file() {
        if (all_markdown && path.extension() == Some(OsStr::new("md")))
            || (!all_markdown && path.file_name() == Some(OsStr::new("SKILL.md")))
        {
            inspect_claude_definition_frontmatter(path, &metadata, require_frontmatter)?;
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Error::PolicyRefused(format!(
            "refusing uninspectable Claude project definition path {}",
            path.display()
        )));
    }
    if depth >= MAX_PROJECT_DEFINITION_DEPTH {
        return Err(Error::PolicyRefused(format!(
            "Claude project definitions below {} exceed the inspection depth limit",
            path.display()
        )));
    }
    let directory = fs::read_dir(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    for entry in directory {
        let entry = entry.map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        *entries += 1;
        if *entries > MAX_PROJECT_DEFINITION_ENTRIES {
            return Err(Error::PolicyRefused(format!(
                "Claude project definitions below {} exceed the inspection entry limit",
                path.display()
            )));
        }
        inspect_claude_definition_tree(
            &entry.path(),
            depth + 1,
            entries,
            all_markdown,
            require_frontmatter,
        )?;
    }
    Ok(())
}

fn inspect_claude_definition_frontmatter(
    path: &Path,
    metadata: &fs::Metadata,
    require_frontmatter: bool,
) -> Result<()> {
    if metadata.len() > MAX_PROJECT_DEFINITION_BYTES {
        return Err(Error::PolicyRefused(format!(
            "Claude project definition {} exceeds the 1 MiB inspection limit",
            path.display()
        )));
    }
    let bytes = fs::read(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let text = str::from_utf8(&bytes).map_err(|_| {
        Error::PolicyRefused(format!(
            "cannot inspect non-UTF-8 Claude project definition {}",
            path.display()
        ))
    })?;
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("---") {
        if !require_frontmatter {
            return Ok(());
        }
        return Err(Error::PolicyRefused(format!(
            "cannot inspect Claude project definition {} without YAML frontmatter",
            path.display()
        )));
    }
    for line in lines {
        if line.trim() == "---" {
            return Ok(());
        }
        if has_unsupported_yaml_key_syntax(line) {
            return Err(Error::PolicyRefused(format!(
                "cannot safely inspect unsupported YAML key syntax in Claude project definition {}",
                path.display()
            )));
        }
        if contains_yaml_hooks_key(line) {
            return Err(Error::PolicyRefused(format!(
                "Claude project definition {} contains executable frontmatter hooks",
                path.display()
            )));
        }
    }
    Err(Error::PolicyRefused(format!(
        "cannot inspect unterminated YAML frontmatter in Claude project definition {}",
        path.display()
    )))
}

fn has_unsupported_yaml_key_syntax(line: &str) -> bool {
    let trimmed = line.trim_start();
    line.contains('\\')
        || line.contains('&')
        || line.contains('*')
        || trimmed.starts_with('?')
        || trimmed.starts_with('[')
        || trimmed.starts_with('{')
}

fn contains_yaml_hooks_key(line: &str) -> bool {
    let lowercase = line.to_ascii_lowercase();
    let bytes = lowercase.as_bytes();
    for (index, _) in lowercase.match_indices("hooks") {
        let before = index.checked_sub(1).and_then(|offset| bytes.get(offset));
        let before_is_boundary = before.is_none_or(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'{' | b',' | b'\'' | b'"')
        });
        if !before_is_boundary {
            continue;
        }
        let mut tail = &bytes[index + "hooks".len()..];
        if tail
            .first()
            .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
        {
            tail = &tail[1..];
        }
        while tail.first().is_some_and(u8::is_ascii_whitespace) {
            tail = &tail[1..];
        }
        if tail.first() == Some(&b':') {
            return true;
        }
    }
    false
}

pub(crate) fn validate_codex_settings(state_dir: &Path, cwd: &Path) -> Result<()> {
    let mut candidates = vec![(state_dir.join("config.toml"), false)];
    for ancestor in project_ancestors(cwd) {
        let hooks = ancestor.join(".codex/hooks.json");
        match fs::symlink_metadata(&hooks) {
            Ok(_) => {
                return Err(Error::PolicyRefused(format!(
                    "Codex project hook configuration {} is not allowed in a wrapped run",
                    hooks.display()
                )));
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::ReadFile {
                    path: hooks,
                    source,
                });
            }
        }
        candidates.push((ancestor.join(".codex/config.toml"), true));
    }

    for (path, untrusted) in candidates {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(Error::ReadFile {
                    path: path.clone(),
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::PolicyRefused(format!(
                "refusing uninspectable Codex config path {}",
                path.display()
            )));
        }
        if metadata.len() > 1024 * 1024 {
            return Err(Error::PolicyRefused(format!(
                "Codex config file {} exceeds the 1 MiB inspection limit",
                path.display()
            )));
        }
        let text = fs::read_to_string(&path).map_err(|source| Error::ReadFile {
            path: path.clone(),
            source,
        })?;
        if let Some(setting) = unsafe_codex_setting(&text, untrusted)? {
            return Err(Error::PolicyRefused(format!(
                "Codex config {} contains unsupported routing or repository command key `{setting}`",
                path.display()
            )));
        }
    }
    Ok(())
}

fn unsafe_codex_setting(text: &str, untrusted: bool) -> Result<Option<String>> {
    let document: toml::Value = toml::from_str(text).map_err(|error| {
        Error::PolicyRefused(format!("cannot inspect invalid Codex config: {error}"))
    })?;
    Ok(find_unsafe_codex_setting(&document, untrusted))
}

fn find_unsafe_codex_setting(value: &toml::Value, untrusted: bool) -> Option<String> {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                if key.eq_ignore_ascii_case("shell_environment_policy") {
                    if untrusted || !is_wrapper_shell_environment_policy(child) {
                        return Some(key.clone());
                    }
                    continue;
                }
                if CODEX_ROUTING_KEYS
                    .iter()
                    .any(|blocked| key.eq_ignore_ascii_case(blocked))
                    || (untrusted
                        && (UNTRUSTED_COMMAND_KEYS
                            .iter()
                            .any(|blocked| key.eq_ignore_ascii_case(blocked))
                            || UNTRUSTED_CODEX_EXTENSION_KEYS
                                .iter()
                                .any(|blocked| key.eq_ignore_ascii_case(blocked))))
                {
                    return Some(key.clone());
                }
                if key.eq_ignore_ascii_case("model_provider")
                    && child.as_str().is_none_or(|provider| provider != "openai")
                {
                    return Some(key.clone());
                }
                if let Some(found) = find_unsafe_codex_setting(child, untrusted) {
                    return Some(found);
                }
            }
            None
        }
        toml::Value::Array(values) => values
            .iter()
            .find_map(|value| find_unsafe_codex_setting(value, untrusted)),
        _ => None,
    }
}

fn is_wrapper_shell_environment_policy(value: &toml::Value) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    table.len() == 2
        && table.get("inherit").and_then(toml::Value::as_str) == Some("core")
        && table
            .get("ignore_default_excludes")
            .and_then(toml::Value::as_bool)
            == Some(false)
}

fn project_ancestors(cwd: &Path) -> Vec<&Path> {
    let ancestors = cwd.ancestors().collect::<Vec<_>>();
    if let Some(index) = ancestors
        .iter()
        .position(|ancestor| ancestor.join(".git").exists())
    {
        return ancestors.into_iter().take(index + 1).collect();
    }
    let home = directories::UserDirs::new()
        .and_then(|directories| directories.home_dir().canonicalize().ok());
    if let Some(index) = home.and_then(|home| {
        ancestors
            .iter()
            .position(|ancestor| ancestor.canonicalize().is_ok_and(|path| path == home))
    }) {
        return ancestors.into_iter().take(index.max(1)).collect();
    }
    ancestors
}

fn validate_current_codex_settings(profile: &Profile) -> Result<()> {
    let cwd = env::current_dir().map_err(|source| Error::ReadFile {
        path: PathBuf::from("."),
        source,
    })?;
    validate_codex_settings(profile.state_dir(), &cwd)
}

fn validate_current_claude_settings(profile: &Profile) -> Result<()> {
    let cwd = env::current_dir().map_err(|source| Error::ReadFile {
        path: PathBuf::from("."),
        source,
    })?;
    validate_claude_settings(profile.state_dir(), &cwd)
}

pub(crate) fn enforce_runner_policy(
    profile: &Profile,
    non_interactive: bool,
    trusted_runner: bool,
) -> Result<()> {
    enforce_pull_request_static_secret_policy(profile)?;

    let requires_trusted_runner = matches!(
        profile,
        Profile::Claude {
            auth: ClaudeAuth::SubscriptionToken,
            ..
        } | Profile::Codex {
            auth: CodexAuth::ChatgptOauth | CodexAuth::AccessToken,
            ..
        }
    );
    if !requires_trusted_runner {
        return Ok(());
    }

    let in_ci = env::var_os("CI").is_some() || non_interactive;
    if in_ci && !trusted_runner {
        return Err(Error::PolicyRefused(
            "subscription and cached OAuth/access-token automation requires `--trusted-runner` on a private runner"
                .to_owned(),
        ));
    }
    Ok(())
}

fn enforce_pull_request_static_secret_policy(profile: &Profile) -> Result<()> {
    let github_event = env::var("GITHUB_EVENT_NAME").unwrap_or_default();
    let is_pull_request = matches!(
        github_event.as_str(),
        "pull_request" | "pull_request_target"
    );
    let exposes_long_lived_credential = profile.requires_static_secret()
        || matches!(
            profile,
            Profile::Codex {
                auth: CodexAuth::ChatgptOauth,
                ..
            }
        );
    if is_pull_request && exposes_long_lived_credential {
        return Err(Error::PolicyRefused(
            "long-lived and static credentials are refused in GitHub pull-request workflows; use protected push/manual jobs or appropriately scoped workload identity"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_forwarded_args(profile: &Profile, args: &[OsString]) -> Result<()> {
    let blocked = match profile.provider() {
        Provider::Claude => [
            "--settings",
            "--mcp-config",
            "--plugin-dir",
            "--plugin-url",
            "--add-dir",
            "--debug",
            "--remote-control",
            "--bg",
            "--background",
            "--tmux",
        ]
        .as_slice(),
        Provider::Codex => [
            "--config",
            "--profile",
            "--cd",
            "--oss",
            "--local-provider",
            "--remote",
            "--remote-auth-token-env",
            "--ignore-user-config",
            "--enable",
            "--disable",
            "--dangerously-bypass-hook-trust",
        ]
        .as_slice(),
    };
    for argument in args
        .iter()
        .take_while(|argument| argument.as_os_str() != "--")
    {
        let Some(argument) = argument.to_str() else {
            continue;
        };
        if let Some(option) = blocked
            .iter()
            .find(|option| argument == **option || argument.starts_with(&format!("{option}=")))
        {
            return Err(Error::PolicyRefused(format!(
                "vendor option `{option}` can bypass profile isolation or load executable configuration"
            )));
        }
        if profile.provider() == Provider::Codex
            && (is_short_option(argument, "-c")
                || is_short_option(argument, "-p")
                || is_short_option(argument, "-C"))
        {
            return Err(Error::PolicyRefused(format!(
                "Codex option `{}` can bypass profile isolation or project-settings inspection",
                &argument[..2]
            )));
        }
        if matches!(
            profile,
            Profile::Claude {
                auth: ClaudeAuth::SubscriptionToken | ClaudeAuth::Wif,
                ..
            }
        ) && (argument == "--bare"
            || argument == "--remote-control"
            || argument.starts_with("--remote-control="))
        {
            return Err(Error::PolicyRefused(
                "Claude --bare/--remote-control can ignore or bypass the selected subscription/WIF mechanism and is valid here only for API-key profiles"
                    .to_owned(),
            ));
        }
    }
    if let Some(command) = first_vendor_command(profile.provider(), args)? {
        let blocked_command = match profile.provider() {
            Provider::Claude => matches!(
                command,
                "auth" | "setup-token" | "gateway" | "mcp" | "plugin" | "plugins" | "agents"
            ),
            Provider::Codex => matches!(
                command,
                "login"
                    | "logout"
                    | "mcp"
                    | "plugin"
                    | "mcp-server"
                    | "app-server"
                    | "remote-control"
                    | "exec-server"
                    | "debug"
            ),
        };
        if blocked_command {
            return Err(Error::PolicyRefused(format!(
                "vendor command `{command}` manages authentication or executable integrations; use the dedicated ctxlane workflow or run it outside ctxlane"
            )));
        }
    }
    Ok(())
}

fn first_vendor_command(provider: Provider, args: &[OsString]) -> Result<Option<&str>> {
    let mut skip_value = false;
    for argument in args {
        if argument == "--" {
            return Ok(None);
        }
        let Some(argument) = argument.to_str() else {
            return Err(Error::PolicyRefused(
                "cannot safely identify a vendor subcommand after a non-UTF-8 leading argument"
                    .to_owned(),
            ));
        };
        if skip_value {
            skip_value = false;
            continue;
        }
        if provider == Provider::Claude
            && (argument == "-p"
                || argument.starts_with("-p=")
                || (argument.starts_with("-p") && argument.len() > 2)
                || argument == "--print"
                || argument.starts_with("--print="))
        {
            return Ok(None);
        }
        if argument.starts_with('-') {
            if is_known_value_option(provider, argument) {
                skip_value = !has_inline_option_value(argument);
                continue;
            }
            if is_known_flag_option(provider, argument) {
                continue;
            }
            return Err(Error::PolicyRefused(format!(
                "cannot safely identify the vendor subcommand after unrecognized leading option `{argument}`"
            )));
        }
        return Ok(Some(argument));
    }
    Ok(None)
}

fn is_known_value_option(provider: Provider, argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);
    if matches!(option, "-m" | "-r" | "-i" | "-s" | "-a") && argument.len() > option.len() {
        return true;
    }
    match provider {
        Provider::Claude => matches!(
            option,
            "-m" | "--model"
                | "--fallback-model"
                | "--permission-mode"
                | "--permission-prompt-tool"
                | "-r"
                | "--resume"
                | "--add-dir"
                | "--session-id"
                | "--agent"
                | "--agents"
                | "--input-format"
                | "--output-format"
                | "--json-schema"
                | "--max-budget-usd"
                | "--max-turns"
                | "--allowedTools"
                | "--disallowedTools"
                | "--tools"
                | "--system-prompt"
                | "--append-system-prompt"
                | "--system-prompt-file"
                | "--append-system-prompt-file"
                | "--name"
                | "--debug-file"
                | "--effort"
                | "--setting-sources"
                | "--file"
                | "--betas"
                | "--from-pr"
        ),
        Provider::Codex => matches!(
            option,
            "-m" | "--model"
                | "-s"
                | "--sandbox"
                | "-a"
                | "--ask-for-approval"
                | "-i"
                | "--image"
                | "--add-dir"
        ),
    }
}

fn is_known_flag_option(provider: Provider, argument: &str) -> bool {
    match provider {
        Provider::Claude => matches!(
            argument,
            "-c" | "--continue"
                | "-v"
                | "--version"
                | "-h"
                | "--help"
                | "--verbose"
                | "--ide"
                | "--chrome"
                | "--no-chrome"
                | "--fork-session"
                | "--include-partial-messages"
                | "--replay-user-messages"
                | "--strict-mcp-config"
                | "--disable-slash-commands"
                | "--no-session-persistence"
                | "--allow-dangerously-skip-permissions"
                | "--dangerously-skip-permissions"
                | "--teleport"
                | "--bare"
        ),
        Provider::Codex => matches!(
            argument,
            "-h" | "--help" | "-V" | "--version" | "--search" | "--no-alt-screen"
        ),
    }
}

fn has_inline_option_value(argument: &str) -> bool {
    argument.contains('=')
        || (matches!(argument.get(..2), Some("-m" | "-r" | "-i" | "-s" | "-a"))
            && argument.len() > 2)
}

fn is_short_option(argument: &str, option: &str) -> bool {
    argument == option || (argument.starts_with(option) && argument.len() > option.len())
}

fn build_environment_without_selected_secret(
    profile: &Profile,
) -> Result<BTreeMap<OsString, OsString>> {
    let mut environment = sanitized_inherited_environment(env::vars_os())?;
    environment.insert(
        "CLAUDE_CONFIG_DIR".into(),
        profile.state_dir().as_os_str().to_owned(),
    );
    environment.insert("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB".into(), "1".into());
    Ok(environment)
}

fn spawn_inherited(
    program: &Path,
    args: &[OsString],
    environment: BTreeMap<OsString, OsString>,
) -> Result<i32> {
    let mut command = Command::new(program);
    let signal_forwarder = SignalForwarder::new().map_err(|source| Error::Spawn {
        program: program.display().to_string(),
        source,
    })?;
    command
        .args(args)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|source| Error::Spawn {
        program: program.display().to_string(),
        source,
    })?;
    drop(command);
    let status = match signal_forwarder.wait(&mut child) {
        Ok(status) => status,
        Err(source) => {
            terminate_and_reap(&mut child);
            return Err(Error::Spawn {
                program: program.display().to_string(),
                source,
            });
        }
    };
    Ok(status_code(status))
}

struct SignalForwarder {
    #[cfg(unix)]
    signals: signal_hook::iterator::Signals,
}

impl SignalForwarder {
    #[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};

            Ok(Self {
                signals: signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP])?,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    fn wait(self, child: &mut Child) -> std::io::Result<ExitStatus> {
        #[cfg(unix)]
        {
            use std::thread;

            use rustix::process::{Pid, Signal, kill_process};
            use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};

            let Self { mut signals } = self;
            let handle = signals.handle();
            let child_pid = Pid::from_child(child);
            let relay = thread::spawn(move || {
                for signal in &mut signals {
                    let forwarded = match signal {
                        SIGINT => Some(Signal::INT),
                        SIGTERM => Some(Signal::TERM),
                        SIGHUP => Some(Signal::HUP),
                        _ => None,
                    };
                    if let Some(forwarded) = forwarded {
                        let _ = kill_process(child_pid, forwarded);
                    }
                }
            });
            let result = child.wait();
            handle.close();
            let _ = relay.join();
            result
        }

        #[cfg(not(unix))]
        {
            let _ = self;
            child.wait()
        }
    }
}

fn status_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(1)
    }

    #[cfg(not(unix))]
    {
        1
    }
}

fn require_secret<'a>(secret: Option<&'a str>, label: &str) -> Result<&'a str> {
    secret
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::CredentialUnavailable {
            profile: label.to_owned(),
            reason: "no credential was resolved".to_owned(),
        })
}

pub(crate) fn is_blocked_key(key: &OsStr) -> bool {
    let key = key.to_string_lossy();
    BLOCKED_ENVIRONMENT
        .iter()
        .any(|blocked| key.eq_ignore_ascii_case(blocked))
        || BLOCKED_ENVIRONMENT_PREFIXES.iter().any(|prefix| {
            key.get(..prefix.len())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        })
        || is_wrapper_environment_key(&key)
        || is_vendor_environment_key(&key)
}

fn is_vendor_environment_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("CLAUDECODE")
        || BLOCKED_VENDOR_ENVIRONMENT_PREFIXES.iter().any(|prefix| {
            key.get(..prefix.len())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use crate::model::{BillingDomain, CodexCredentialStore, WifConfig};

    use super::*;

    // This fixture deliberately leaves a finite-lived descendant holding stdout open so the
    // caller can prove that output capture never waits for a process it does not own.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn preflight_sleep_fixture() {
        if env::var_os("CTXLANE_TEST_PREFLIGHT_DESCENDANT").is_some() {
            let program = env::current_exe()
                .unwrap_or_else(|error| panic!("resolve descendant test executable: {error}"));
            Command::new(program)
                .arg("--exact")
                .arg("runner::tests::preflight_sleep_fixture")
                .env_remove("CTXLANE_TEST_PREFLIGHT_DESCENDANT")
                .env("CTXLANE_TEST_PREFLIGHT_DESCENDANT_CHILD", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|error| panic!("spawn descendant preflight fixture: {error}"));
            if let Some(marker) = env::var_os("CTXLANE_TEST_PREFLIGHT_READY") {
                fs::write(PathBuf::from(marker), b"ready")
                    .unwrap_or_else(|error| panic!("write descendant readiness marker: {error}"));
            }
        } else if env::var_os("CTXLANE_TEST_PREFLIGHT_DESCENDANT_CHILD").is_some() {
            thread::sleep(Duration::from_secs(2));
            if let Some(marker) = env::var_os("CTXLANE_TEST_PREFLIGHT_READY") {
                let marker = PathBuf::from(marker);
                if marker.exists() {
                    fs::remove_file(marker).unwrap_or_else(|error| {
                        panic!("remove descendant readiness marker: {error}")
                    });
                }
            }
        } else if env::var_os("CTXLANE_TEST_PREFLIGHT_SLEEP").is_some() {
            thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn preflight_timeout_kills_reaps_and_unblocks_output_capture() {
        let temporary = TempDir::new()
            .unwrap_or_else(|error| panic!("create preflight fixture tempdir: {error}"));
        let program = env::current_exe()
            .unwrap_or_else(|error| panic!("resolve current test executable: {error}"));
        let mut command = Command::new(&program);
        command
            .arg("--exact")
            .arg("runner::tests::preflight_sleep_fixture")
            .env("CTXLANE_TEST_PREFLIGHT_SLEEP", "1")
            // This subprocess is the kill target. Its parent remains instrumented, while an
            // incomplete profile from the terminated child stays outside the coverage merge.
            .env_remove("LLVM_PROFILE_FILE")
            .current_dir(temporary.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("spawn sleeping preflight fixture: {error}"));
        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("sleeping fixture should have piped stdout"));
        let started = Instant::now();
        let result = capture_preflight_stdout(
            &mut child,
            stdout,
            &program,
            "test preflight",
            Duration::from_millis(100),
        );
        let error = match result {
            Ok((status, _)) => panic!("sleeping preflight unexpectedly exited with {status}"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::VendorIncompatible(_)));
        assert!(error.to_string().contains("100ms preflight limit"));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "preflight timeout did not return promptly"
        );
        assert!(
            child
                .try_wait()
                .unwrap_or_else(|error| panic!("inspect reaped child: {error}"))
                .is_some(),
            "timed-out preflight child was not reaped"
        );
    }

    #[test]
    fn preflight_timeout_does_not_wait_for_inherited_stdout() {
        let temporary = TempDir::new()
            .unwrap_or_else(|error| panic!("create preflight fixture tempdir: {error}"));
        let ready = temporary.path().join("descendant-ready");
        let program = env::current_exe()
            .unwrap_or_else(|error| panic!("resolve current test executable: {error}"));
        let mut command = Command::new(&program);
        command
            .arg("--exact")
            .arg("runner::tests::preflight_sleep_fixture")
            .env("CTXLANE_TEST_PREFLIGHT_DESCENDANT", "1")
            .env("CTXLANE_TEST_PREFLIGHT_READY", &ready)
            // The finite-lived descendant intentionally outlives its direct parent. Do not let
            // either fixture race cargo-llvm-cov's merge after this test has completed.
            .env_remove("LLVM_PROFILE_FILE")
            .current_dir(temporary.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("spawn descendant preflight fixture: {error}"));
        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("descendant fixture should have piped stdout"));
        let ready_deadline = Instant::now() + Duration::from_secs(3);
        while !ready.exists() {
            if child
                .try_wait()
                .unwrap_or_else(|error| panic!("inspect descendant fixture startup: {error}"))
                .is_some()
            {
                panic!("preflight fixture exited before spawning its descendant");
            }
            if Instant::now() >= ready_deadline {
                terminate_and_reap(&mut child);
                panic!("timed out waiting for descendant readiness marker");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let started = Instant::now();
        let result = capture_preflight_stdout(
            &mut child,
            stdout,
            &program,
            "test descendant preflight",
            Duration::from_millis(100),
        );
        let error = match result {
            Ok((status, _)) => panic!("inherited pipe unexpectedly closed with {status}"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::VendorIncompatible(_)));
        assert!(error.to_string().contains("100ms preflight limit"));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "preflight waited for a descendant that inherited stdout"
        );
        assert!(
            child
                .try_wait()
                .unwrap_or_else(|error| panic!("inspect completed child: {error}"))
                .is_some(),
            "direct preflight child was not reaped"
        );

        let cleanup_deadline = Instant::now() + Duration::from_secs(3);
        while ready.exists() {
            assert!(
                Instant::now() < cleanup_deadline,
                "descendant fixture did not finish"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn claude_profile(auth: ClaudeAuth) -> Profile {
        Profile::Claude {
            billing_domain: if auth == ClaudeAuth::SubscriptionToken {
                BillingDomain::ClaudeSubscription
            } else {
                BillingDomain::AnthropicApi
            },
            auth,
            state_dir: PathBuf::from("/tmp/ctxlane-claude"),
            secret_ref: None,
            account_hint: None,
            expected_organization: None,
            wif: (auth == ClaudeAuth::Wif).then(|| WifConfig {
                organization_id: "org".to_owned(),
                federation_rule_id: "rule".to_owned(),
                service_account_id: "service".to_owned(),
                workspace_id: Some("workspace".to_owned()),
                identity_token_file: PathBuf::from("/tmp/token"),
            }),
        }
    }

    fn codex_api_profile() -> Profile {
        Profile::Codex {
            billing_domain: BillingDomain::OpenaiApi,
            auth: CodexAuth::ApiKey,
            state_dir: PathBuf::from("/tmp/ctxlane-codex"),
            secret_ref: Some("keyring://ctxlane/codex-api-key".to_owned()),
            account_hint: None,
            expected_workspace_id: None,
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: false,
        }
    }

    #[test]
    fn subscription_profile_removes_competing_credentials_and_endpoints() {
        let profile = claude_profile(ClaudeAuth::SubscriptionToken);
        let base = [
            ("LANG", "C"),
            ("ANTHROPIC_API_KEY", "wrong-billing"),
            ("ANTHROPIC_AUTH_TOKEN", "wrong-gateway"),
            ("ANTHROPIC_IDENTITY_TOKEN", "wrong-wif-token"),
            ("ANTHROPIC_BASE_URL", "https://attacker.invalid"),
            ("CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "wrong-refresh-token"),
            ("OPENAI_API_KEY", "unrelated-secret"),
            ("NODE_OPTIONS", "--require=/untrusted/preload.js"),
            ("LD_PRELOAD", "/untrusted/library.so"),
            ("HTTPS_PROXY", "https://attacker.invalid"),
            ("SSL_CERT_FILE", "/untrusted/ca.pem"),
            ("CLAUDE_ENV_FILE", "/untrusted/env"),
            ("CLAUDE_CODE_SHELL_PREFIX", "steal"),
            ("CLAUDE_CODE_SHELL", "/untrusted/shell"),
            ("CLAUDE_CODE_GIT_BASH_PATH", "/untrusted/bash"),
            ("CLAUDE_CODE_PLUGIN_SEED_DIR", "/untrusted/plugins"),
            ("ANTHROPIC_CUSTOM_HEADERS", "x-steal: value"),
            ("CLAUDE_CODE_USE_BEDROCK", "1"),
            ("CLAUDECODE", "1"),
            ("SHELL", "/untrusted/shell"),
            ("ZDOTDIR", "/untrusted/zsh"),
            ("NODE_TLS_REJECT_UNAUTHORIZED", "0"),
            ("GIT_SSH_COMMAND", "steal"),
            ("AICTX_CONTEXT", "wrong-context"),
        ];
        let environment = build_environment(&profile, Some("selected"), base)
            .unwrap_or_else(|error| panic!("environment should build: {error}"));
        assert_eq!(
            environment.get(OsStr::new("LANG")),
            Some(&OsString::from("C"))
        );
        assert!(!environment.contains_key(OsStr::new("ANTHROPIC_API_KEY")));
        assert!(!environment.contains_key(OsStr::new("ANTHROPIC_AUTH_TOKEN")));
        assert!(!environment.contains_key(OsStr::new("ANTHROPIC_IDENTITY_TOKEN")));
        assert!(!environment.contains_key(OsStr::new("ANTHROPIC_BASE_URL")));
        assert!(!environment.contains_key(OsStr::new("CLAUDE_CODE_OAUTH_REFRESH_TOKEN")));
        assert!(!environment.contains_key(OsStr::new("OPENAI_API_KEY")));
        assert!(!environment.contains_key(OsStr::new("NODE_OPTIONS")));
        assert!(!environment.contains_key(OsStr::new("LD_PRELOAD")));
        assert!(!environment.contains_key(OsStr::new("HTTPS_PROXY")));
        assert!(!environment.contains_key(OsStr::new("SSL_CERT_FILE")));
        assert!(!environment.contains_key(OsStr::new("CLAUDE_ENV_FILE")));
        assert!(!environment.contains_key(OsStr::new("CLAUDE_CODE_SHELL_PREFIX")));
        assert!(!environment.contains_key(OsStr::new("ANTHROPIC_CUSTOM_HEADERS")));
        assert!(!environment.contains_key(OsStr::new("CLAUDE_CODE_USE_BEDROCK")));
        assert!(!environment.contains_key(OsStr::new("CLAUDECODE")));
        assert!(!environment.contains_key(OsStr::new("SHELL")));
        assert!(!environment.contains_key(OsStr::new("ZDOTDIR")));
        assert!(!environment.contains_key(OsStr::new("NODE_TLS_REJECT_UNAUTHORIZED")));
        assert!(!environment.contains_key(OsStr::new("GIT_SSH_COMMAND")));
        assert!(!environment.contains_key(OsStr::new("AICTX_CONTEXT")));
        assert_eq!(
            environment.get(OsStr::new("CLAUDE_CODE_OAUTH_TOKEN")),
            Some(&OsString::from("selected"))
        );
        assert_eq!(
            environment.get(OsStr::new("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB")),
            Some(&OsString::from("1"))
        );
    }

    #[test]
    fn inherited_application_environment_prefixes_are_scrubbed() {
        let environment = sanitized_inherited_environment([
            ("LANG", "C"),
            ("AICTX_PROFILE", "legacy-profile"),
            ("AICTX_FUTURE_SELECTOR", "legacy-future"),
            ("aictx_lowercase_future", "legacy-lowercase"),
            ("CTXLANE_CONTEXT", "target-context"),
            ("CTXLANE_FUTURE_SELECTOR", "target-future"),
            ("ctxlane_lowercase_future", "target-lowercase"),
            ("NOT_AICTX_PROFILE", "keep-me"),
        ])
        .unwrap_or_else(|error| panic!("environment should sanitize: {error}"));

        assert_eq!(
            environment.get(OsStr::new("LANG")),
            Some(&OsString::from("C"))
        );
        assert_eq!(
            environment.get(OsStr::new("NOT_AICTX_PROFILE")),
            Some(&OsString::from("keep-me"))
        );
        for key in [
            "AICTX_PROFILE",
            "AICTX_FUTURE_SELECTOR",
            "aictx_lowercase_future",
            "CTXLANE_CONTEXT",
            "CTXLANE_FUTURE_SELECTOR",
            "ctxlane_lowercase_future",
        ] {
            assert!(!environment.contains_key(OsStr::new(key)), "key={key}");
        }
    }

    #[test]
    fn wif_sets_only_documented_identity_selectors() {
        let profile = claude_profile(ClaudeAuth::Wif);
        let environment = build_environment(
            &profile,
            None,
            [("ANTHROPIC_API_KEY", "stale"), ("PATH", "/bin")],
        )
        .unwrap_or_else(|error| panic!("environment should build: {error}"));
        assert!(!environment.contains_key(OsStr::new("ANTHROPIC_API_KEY")));
        assert_eq!(
            environment.get(OsStr::new("ANTHROPIC_FEDERATION_RULE_ID")),
            Some(&OsString::from("rule"))
        );
        assert_eq!(
            environment.get(OsStr::new("ANTHROPIC_IDENTITY_TOKEN_FILE")),
            Some(&OsString::from("/tmp/token"))
        );
        assert_eq!(
            environment.get(OsStr::new("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB")),
            Some(&OsString::from("1"))
        );
    }

    #[test]
    fn settings_scanner_finds_nested_helpers() {
        let document = serde_json::json!({"nested": {"apiKeyHelper": "do-not-run"}});
        assert!(contains_competing_claude_setting(&document, true));
        for key in UNTRUSTED_CLAUDE_PLUGIN_KEYS {
            let document = serde_json::json!({(*key): {"attacker": true}});
            assert!(contains_competing_claude_setting(&document, true));
            assert!(
                !contains_competing_claude_setting(&document, false),
                "trusted profile-local setting `{key}` should not be treated as repository input"
            );
        }
        for key in UNTRUSTED_CLAUDE_EXECUTABLE_KEYS {
            let document = serde_json::json!({(*key): {"command": "steal"}});
            assert!(contains_competing_claude_setting(&document, true));
            assert!(!contains_competing_claude_setting(&document, false));
        }
        assert!(contains_competing_claude_setting(
            &serde_json::json!({"env": {"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0"}}),
            true
        ));
        assert!(contains_competing_claude_setting(
            &serde_json::json!({"nested": {"env": {"CLAUDE_CODE_SHELL_PREFIX": "steal"}}}),
            true
        ));
        assert!(!contains_competing_claude_setting(
            &serde_json::json!({"env": {"DISPLAY": ":0"}}),
            false
        ));
        assert!(contains_competing_claude_setting(
            &serde_json::json!({"ANTHROPIC_CUSTOM_HEADERS": "x-steal: value"}),
            false
        ));
        assert!(contains_competing_claude_setting(
            &serde_json::json!({"CLAUDE_CODE_USE_BEDROCK": true}),
            false
        ));
        let safe = serde_json::json!({"permissions": {"allow": ["Read"]}});
        assert!(!contains_competing_claude_setting(&safe, true));
    }

    #[test]
    fn claude_frontmatter_rejects_escaped_or_complex_yaml_keys() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        for (name, frontmatter) in [
            (
                "escaped.md",
                r#"---
"h\u006foks": {}
---
Body
"#,
            ),
            ("complex.md", "---\n? [hooks]\n: {}\n---\nBody\n"),
            (
                "alias.md",
                "---\nname: &hook_name hooks\n*hook_name: {}\n---\nBody\n",
            ),
        ] {
            let path = temporary.path().join(name);
            fs::write(&path, frontmatter)
                .unwrap_or_else(|error| panic!("write frontmatter case: {error}"));
            let metadata = fs::metadata(&path)
                .unwrap_or_else(|error| panic!("read frontmatter metadata: {error}"));
            let Err(error) = inspect_claude_definition_frontmatter(&path, &metadata, true) else {
                panic!("unsupported YAML syntax should be rejected");
            };
            assert!(error.to_string().contains("unsupported YAML key syntax"));
        }
    }

    #[test]
    fn codex_settings_scanner_rejects_project_commands_and_routes() {
        assert_eq!(
            unsafe_codex_setting("model_provider = 'third-party'", true)
                .unwrap_or_else(|error| panic!("valid TOML: {error}")),
            Some("model_provider".to_owned())
        );
        assert_eq!(
            unsafe_codex_setting("openai_base_url = 'https://attacker.invalid'", false)
                .unwrap_or_else(|error| panic!("valid TOML: {error}")),
            Some("openai_base_url".to_owned())
        );
        assert_eq!(
            unsafe_codex_setting("[mcp_servers.evil]\ncommand = 'steal'", true)
                .unwrap_or_else(|error| panic!("valid TOML: {error}")),
            Some("mcp_servers".to_owned())
        );
        assert_eq!(
            unsafe_codex_setting("model_provider = 'openai'", false)
                .unwrap_or_else(|error| panic!("valid TOML: {error}")),
            None
        );
        for key in UNTRUSTED_CODEX_EXTENSION_KEYS {
            let text = format!("{key} = {{ attacker = true }}");
            assert_eq!(
                unsafe_codex_setting(&text, true)
                    .unwrap_or_else(|error| panic!("valid TOML for {key}: {error}")),
                Some((*key).to_owned())
            );
        }
        assert_eq!(
            unsafe_codex_setting(
                "[shell_environment_policy]\ninherit = 'all'\nignore_default_excludes = true",
                false
            )
            .unwrap_or_else(|error| panic!("valid unsafe shell policy: {error}")),
            Some("shell_environment_policy".to_owned())
        );
        assert_eq!(
            unsafe_codex_setting(
                "[shell_environment_policy]\ninherit = 'core'\nignore_default_excludes = false",
                false
            )
            .unwrap_or_else(|error| panic!("valid wrapper shell policy: {error}")),
            None
        );
    }

    #[test]
    fn forwarded_command_detection_ignores_prompt_positions() {
        let claude = claude_profile(ClaudeAuth::ApiKey);
        let codex = codex_api_profile();
        assert!(validate_forwarded_args(&claude, &["-p".into(), "auth".into()]).is_ok());
        assert!(validate_forwarded_args(&codex, &["exec".into(), "login".into()]).is_ok());
        assert!(validate_forwarded_args(&claude, &["auth".into()]).is_err());
        assert!(validate_forwarded_args(&codex, &["login".into()]).is_err());
        assert!(validate_forwarded_args(&claude, &["--ide".into(), "auth".into()]).is_err());
        assert!(
            validate_forwarded_args(&claude, &["--debug".into(), "filter".into(), "auth".into()])
                .is_err()
        );
        assert!(
            validate_forwarded_args(
                &claude,
                &["--remote-control".into(), "session".into(), "auth".into()]
            )
            .is_err()
        );
        for option in [
            "--name",
            "--debug-file",
            "--effort",
            "--setting-sources",
            "--file",
            "--betas",
        ] {
            assert!(
                validate_forwarded_args(&claude, &[option.into(), "value".into(), "auth".into()])
                    .is_err(),
                "{option} must not hide a blocked subcommand"
            );
        }
        assert!(
            validate_forwarded_args(&claude, &["--unknown-future-option".into(), "value".into()])
                .is_err()
        );
        assert!(
            validate_forwarded_args(
                &claude_profile(ClaudeAuth::Wif),
                &["--remote-control=127.0.0.1:9000".into()]
            )
            .is_err()
        );
    }

    #[test]
    fn codex_api_key_is_not_exposed_to_the_main_vendor_environment() {
        let environment = build_environment(
            &codex_api_profile(),
            Some("selected-api-key"),
            [
                ("OPENAI_API_KEY", "inherited-api-key"),
                ("OPENAI_ORGANIZATION", "wrong-org"),
                ("OPENAI_PROJECT", "wrong-project"),
                ("PATH", "/bin"),
            ],
        )
        .unwrap_or_else(|error| panic!("environment should build: {error}"));
        assert!(!environment.contains_key(OsStr::new("OPENAI_API_KEY")));
        assert!(!environment.contains_key(OsStr::new("OPENAI_ORGANIZATION")));
        assert!(!environment.contains_key(OsStr::new("OPENAI_PROJECT")));
        assert_eq!(
            environment.get(OsStr::new("CODEX_HOME")),
            Some(&OsString::from("/tmp/ctxlane-codex"))
        );
    }
}
