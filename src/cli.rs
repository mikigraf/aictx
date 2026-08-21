use std::{ffi::OsString, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::model::{AuthArg, CodexCredentialStore, Name, ProfileId, Provider};

#[derive(Debug, Parser)]
#[command(
    name = "ctxlane",
    version,
    about = "Switch between Claude Code and Codex accounts with isolated local state",
    long_about = None,
    propagate_version = true,
    after_help = "Run `ctxlane` with no subcommand to open the interactive terminal dashboard.",
    after_long_help = "Examples:\n  ctxlane init --guided\n  ctxlane init\n  ctxlane profile add claude personal --auth subscription\n  ctxlane profile add codex personal --auth subscription\n  ctxlane context add personal --claude claude:personal --codex codex:personal\n  ctxlane use personal\n  ctxlane run claude -- -p \"explain this repository\""
)]
pub struct Cli {
    /// Use an explicit application root outside the current repository.
    #[arg(
        long,
        global = true,
        value_name = "ABSOLUTE_PATH",
        help_heading = "Global options"
    )]
    pub root: Option<PathBuf>,

    /// Use this trusted Claude executable for the current invocation.
    #[arg(
        long,
        global = true,
        value_name = "ABSOLUTE_PATH",
        help_heading = "Global options"
    )]
    pub claude_bin: Option<PathBuf>,

    /// Use this trusted Codex executable for the current invocation.
    #[arg(
        long,
        global = true,
        value_name = "ABSOLUTE_PATH",
        help_heading = "Global options"
    )]
    pub codex_bin: Option<PathBuf>,

    /// Fail instead of opening a browser, prompting, or unlocking an OS keyring.
    #[arg(long, global = true, help_heading = "Global options")]
    pub non_interactive: bool,

    /// Suppress informational banners; security warnings and errors are still shown.
    #[arg(long, global = true, help_heading = "Global options")]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize versioned metadata and secure application directories.
    Init(InitArgs),
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
    /// Copy an existing aictx store without moving or deleting source data.
    Migrate(MigrateArgs),
}

#[derive(Debug, Args)]
pub struct MigrateArgs {
    #[command(subcommand)]
    pub command: MigrateCommand,
}

#[derive(Debug, Subcommand)]
pub enum MigrateCommand {
    /// Inspect or copy the legacy aictx store without moving or deleting source data.
    Aictx(MigrateAictxArgs),
    /// Clean up or finalize an interrupted aictx-to-ctxlane migration.
    Recover(MigrateRecoverArgs),
}

#[derive(Debug, Args)]
#[command(
    after_long_help = "Examples:\n  ctxlane migrate aictx --dry-run\n  ctxlane migrate aictx\n  ctxlane --root /new/ctxlane migrate aictx --from-root /old/aictx"
)]
pub struct MigrateAictxArgs {
    /// Read the legacy aictx store from this absolute root.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    pub from_root: Option<PathBuf>,

    /// Validate and describe the copy without creating target files.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
#[command(
    after_long_help = "Examples:\n  ctxlane migrate recover\n  ctxlane --root /new/ctxlane migrate recover --from-root /old/aictx"
)]
pub struct MigrateRecoverArgs {
    /// Read the legacy aictx store from this absolute root.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    pub from_root: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(
    after_long_help = "Examples:\n  ctxlane init\n  ctxlane init --guided\n  ctxlane init --fresh\n  ctxlane init --guided --fresh\n\nGuided setup creates or reuses the Claude `personal` subscription-token profile, runs the official `claude setup-token` flow, and stores the pasted token in the OS keyring. On success, run:\n  ctxlane run --profile claude:personal claude -- -p \"explain this repository\""
)]
pub struct InitArgs {
    /// Set up the Claude `personal` subscription profile and credential in one guided flow.
    #[arg(long)]
    pub guided: bool,

    /// Allow a separate empty ctxlane store when legacy metadata is detected.
    #[arg(long)]
    pub fresh: bool,
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
#[command(
    after_long_help = "Examples:\n  ctxlane profile add claude personal --auth subscription\n  ctxlane profile add codex work --auth subscription\n  ctxlane profile add claude ci --auth wif --organization-id org_123 --federation-rule-id rule_123 --identity-token-file /run/secrets/anthropic.jwt"
)]
pub struct ProfileAddArgs {
    /// Vendor that owns the profile: `claude` or `codex`.
    #[arg(value_enum)]
    pub provider: Provider,
    /// Short local name used in the profile ID, for example `personal` or `work`.
    pub name: Name,

    /// Authentication mechanism. Use `subscription` for either subscription provider.
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
    /// Confirm an account-profile change without an interactive prompt.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Debug, Args)]
#[command(
    after_long_help = "Examples:\n  ctxlane login claude:personal --generate\n  ctxlane login codex:work\n  ctxlane login codex:work --device"
)]
pub struct LoginArgs {
    /// Provider profile ID, for example `claude:personal` or `codex:work`.
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
#[command(
    after_long_help = "Examples:\n  ctxlane run claude -- -p \"explain this repository\"\n  ctxlane run codex -- exec \"run the tests\"\n  ctxlane run --profile codex:work codex -- exec \"review this change\""
)]
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
    /// Emit a stable JSON report for support bundles and automation.
    #[arg(long)]
    pub json: bool,
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
            "ctxlane",
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
        let cli = Cli::try_parse_from(["ctxlane"])
            .unwrap_or_else(|error| panic!("interactive CLI should parse: {error}"));
        assert!(cli.command.is_none());
    }
}
