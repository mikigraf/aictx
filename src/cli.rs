use std::{ffi::OsString, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::model::{AuthArg, CodexCredentialStore, Name, ProfileId, Provider};

#[derive(Debug, Parser)]
#[command(
    name = "aictx",
    version,
    about = "Run Claude Code and Codex under explicit, isolated identity and billing contexts",
    long_about = None,
    disable_help_subcommand = true,
    propagate_version = true,
    after_help = "Run `aictx` with no subcommand to open the interactive terminal dashboard."
)]
pub struct Cli {
    /// Use an explicit application root outside the current repository.
    #[arg(long, global = true, value_name = "ABSOLUTE_PATH")]
    pub root: Option<PathBuf>,

    /// Use this trusted Claude executable for the current invocation.
    #[arg(long, global = true, value_name = "ABSOLUTE_PATH")]
    pub claude_bin: Option<PathBuf>,

    /// Use this trusted Codex executable for the current invocation.
    #[arg(long, global = true, value_name = "ABSOLUTE_PATH")]
    pub codex_bin: Option<PathBuf>,

    /// Fail instead of opening a browser, prompting, or unlocking an OS keyring.
    #[arg(long, global = true)]
    pub non_interactive: bool,

    /// Suppress informational banners; security warnings and errors are still shown.
    #[arg(long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize versioned metadata and secure application directories.
    Init,
    /// Add, inspect, list, or remove provider profiles.
    Profile(ProfileArgs),
    /// Add, inspect, list, or remove user-facing contexts.
    Context(ContextArgs),
    /// Select the active context without copying or exporting credentials.
    Use(UseArgs),
    /// Print the context selected for the current directory.
    Current,
    /// Run a vendor-owned authentication flow or store a static credential.
    Login(LoginArgs),
    /// Remove local authentication state using the vendor-supported mechanism.
    Logout(LogoutArgs),
    /// Run an official vendor CLI in the resolved profile.
    Run(RunArgs),
    /// Show selected profiles, billing domains, and credential metadata.
    Status(StatusArgs),
    /// Bind a directory tree to a context in user-owned global metadata.
    Bind(BindArgs),
    /// Remove a directory binding.
    Unbind(UnbindArgs),
    /// List configured directory bindings.
    Bindings,
    /// Check configuration, permissions, binaries, isolation, and inherited credentials.
    Doctor(DoctorArgs),
    /// Check whether configured credentials are available.
    Credential(CredentialArgs),
    /// Emit non-secret environment selectors for a shell.
    Env(EnvArgs),
    /// Emit safe shell function shims for Claude and Codex.
    ShellInit(ShellInitArgs),
    /// Generate static shell completion definitions.
    Completions(CompletionsArgs),
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub command: ProfileCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Add a provider profile with a validated authentication/billing combination.
    Add(ProfileAddArgs),
    /// List profiles without resolving or exposing credentials.
    List,
    /// Show one profile's non-secret metadata.
    Show { profile: ProfileId },
    /// Remove metadata and detach managed vendor state. Does not revoke remotely.
    Remove {
        profile: ProfileId,
        /// Also delete the wrapper-held OS-keyring credential.
        #[arg(long)]
        delete_secret: bool,
    },
}

#[derive(Debug, Args)]
pub struct ProfileAddArgs {
    #[arg(value_enum)]
    pub provider: Provider,
    pub name: Name,

    /// Authentication mechanism; only provider-compatible modes are accepted.
    #[arg(long, value_enum)]
    pub auth: AuthArg,

    /// OS-keyring reference in the form `keyring://service/account`.
    #[arg(long)]
    pub secret_ref: Option<String>,

    /// Display-only account label (for example an email); masked in normal status output.
    #[arg(long)]
    pub account: Option<String>,

    /// Expected Claude organization label or ID.
    #[arg(long)]
    pub organization: Option<String>,

    /// Expected Codex/ChatGPT workspace ID, or optional Anthropic WIF workspace ID.
    #[arg(long)]
    pub workspace: Option<String>,

    /// Anthropic WIF organization ID.
    #[arg(long, requires = "federation_rule_id")]
    pub organization_id: Option<String>,

    /// Anthropic WIF federation rule ID.
    #[arg(long, requires = "organization_id")]
    pub federation_rule_id: Option<String>,

    /// Anthropic WIF service account ID.
    #[arg(long)]
    pub service_account_id: Option<String>,

    /// File populated by the upstream identity provider with an OIDC identity token.
    #[arg(long)]
    pub identity_token_file: Option<PathBuf>,

    /// Codex's vendor-owned credential storage policy inside the isolated `CODEX_HOME`.
    #[arg(long, value_enum, default_value_t)]
    pub codex_credential_store: CodexCredentialStore,
}

#[derive(Debug, Args)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub command: ContextCommand,
}

#[derive(Debug, Subcommand)]
pub enum ContextCommand {
    /// Add a context mapping to one or both provider profiles.
    Add {
        name: Name,
        #[arg(long)]
        claude: Option<ProfileId>,
        #[arg(long)]
        codex: Option<ProfileId>,
    },
    /// List contexts.
    List,
    /// Show one context.
    Show { name: Name },
    /// Remove a context that is not active or referenced by bindings.
    Remove { name: Name },
}

#[derive(Debug, Args)]
pub struct UseArgs {
    pub context: Name,
    /// Confirm a billing-domain change without an interactive prompt.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    pub profile: ProfileId,
    /// Use Codex's official device authorization flow.
    #[arg(long)]
    pub device: bool,
    /// Run `claude setup-token` before securely prompting for the resulting token.
    #[arg(long)]
    pub generate: bool,
    /// Explicitly assert that the current CI/automation runner is private and trusted.
    #[arg(long)]
    pub trusted_runner: bool,
}

#[derive(Debug, Args)]
pub struct LogoutArgs {
    pub profile: ProfileId,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Resolve this context for one invocation without changing active state.
    #[arg(long, conflicts_with = "profile")]
    pub context: Option<Name>,
    /// Run one explicit provider profile, bypassing context resolution.
    #[arg(long, conflicts_with = "context")]
    pub profile: Option<ProfileId>,
    /// Explicitly assert that the current CI/automation runner is private and trusted.
    #[arg(long)]
    pub trusted_runner: bool,
    #[arg(value_enum)]
    pub provider: Provider,
    /// Accepted arguments forwarded unchanged to the official vendor executable.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Inspect this context without changing active state.
    #[arg(long)]
    pub context: Option<Name>,
    /// Include state paths, masked identity pins, and credential availability.
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Debug, Args)]
pub struct BindArgs {
    pub path: PathBuf,
    pub context: Name,
}

#[derive(Debug, Args)]
pub struct UnbindArgs {
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long, value_enum)]
    pub provider: Option<Provider>,
}

#[derive(Debug, Args)]
pub struct CredentialArgs {
    #[command(subcommand)]
    pub command: CredentialCommand,
}

#[derive(Debug, Subcommand)]
pub enum CredentialCommand {
    /// Check one profile or every profile without printing secret values.
    Check {
        profile: Option<ProfileId>,
        #[arg(long, conflicts_with = "profile")]
        all: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[clap(rename_all = "lower")]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

#[derive(Debug, Args)]
pub struct EnvArgs {
    #[arg(long)]
    pub context: Option<Name>,
    #[arg(long, value_enum)]
    pub shell: Shell,
}

#[derive(Debug, Args)]
pub struct ShellInitArgs {
    #[arg(value_enum)]
    pub shell: Shell,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_preserves_hostile_arguments_as_values() {
        let cli = Cli::try_parse_from([
            "aictx",
            "run",
            "claude",
            "--",
            "$(touch /tmp/nope)",
            "semi;colon",
            "two words",
        ])
        .unwrap_or_else(|error| panic!("valid CLI: {error}"));
        let Some(Command::Run(run)) = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(run.args.len(), 3);
        assert_eq!(run.args[0], "$(touch /tmp/nope)");
    }

    #[test]
    fn no_subcommand_selects_interactive_mode() {
        let cli = Cli::try_parse_from(["aictx"])
            .unwrap_or_else(|error| panic!("interactive CLI should parse: {error}"));
        assert!(cli.command.is_none());
    }
}
