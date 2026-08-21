use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use secrecy::SecretString;

use crate::{
    Error, Result, activation,
    binary::is_in_current_repository,
    cli::{
        Cli, Command, ContextCommand, CredentialCommand, InitArgs, LoginArgs, MigrateCommand,
        ProfileAddArgs, ProfileCommand,
    },
    config::{AppPaths, MetadataStore, acquire_profile_lock, ensure_secure_directory},
    doctor,
    identity::{LEGACY_AICTX, TARGET_CTXLANE},
    migration::{
        MigrationPlan, MigrationSummary, RecoveryOutcome, migration_journal_path,
        recover_incomplete,
    },
    model::{
        AuthArg, BillingDomain, ClaudeAuth, CodexAuth, CodexCredentialStore, Config, Context, Name,
        Profile, ProfileId, Provider, WifConfig,
    },
    resolver::{
        binding_lookup_path, canonical_directory, context_not_found, current_directory,
        profile_not_found, resolve_context, resolve_profile,
    },
    runner::{
        CredentialState, RunOptions, codex_static_login, credential_state, enforce_runner_policy,
        generate_claude_setup_token, login_codex, logout_codex, run_profile,
        validate_codex_settings,
    },
    secret::{
        SecretManager, SecretRef, parse_profile_secret_ref, prompt_claude_setup_token,
        prompt_secret, secret_label,
    },
    shell, tui,
};

pub fn execute(cli: Cli, paths: &AppPaths) -> Result<i32> {
    let store = MetadataStore::new(paths.clone());
    match cli.command {
        None => tui::run(&store, cli.non_interactive),
        Some(Command::Init(args)) => {
            execute_init(&store, paths, &args, cli.non_interactive, cli.quiet)
        }
        Some(Command::Profile(args)) => {
            execute_profile(&store, paths, args.command, cli.non_interactive)
        }
        Some(Command::Context(args)) => execute_context(&store, args.command),
        Some(Command::Use(args)) => {
            let selection_change = activation::required_selection_change(&store, &args.context)?;
            if let Some(change) = selection_change.as_ref().filter(|_| !args.yes) {
                if cli.non_interactive {
                    return Err(Error::InteractionRequired(
                        "account profile change requires `aictx use --yes`".to_owned(),
                    ));
                }
                print_selection_change(change);
                if !confirm(
                    "Continue? [y/N] ",
                    "account profile confirmation requires a terminal or `aictx use --yes`",
                )? {
                    return Err(Error::Cancelled);
                }
            }
            let confirmation = if args.yes {
                activation::SelectionConfirmation::AnyChange
            } else {
                selection_change.map_or(
                    activation::SelectionConfirmation::None,
                    activation::SelectionConfirmation::Change,
                )
            };
            let cwd = current_directory()?;
            let receipt =
                activation::activate_with_receipt(&store, &args.context, &confirmation, &cwd)?;
            print_activation_receipt(&receipt);
            Ok(0)
        }
        Some(Command::Current) => {
            let (config, state) = store.load_metadata()?;
            let cwd = current_directory()?;
            let context = resolve_context(&config, &state, &cwd, None)?;
            println!("{}", context.name);
            Ok(0)
        }
        Some(Command::Login(args)) => {
            execute_login(&store, paths, &args, cli.non_interactive, false)
        }
        Some(Command::Logout(args)) => {
            execute_logout(&store, paths, &args.profile, cli.non_interactive)
        }
        Some(Command::Run(args)) => {
            let (config, state) = store.load_metadata()?;
            let cwd = current_directory()?;
            let resolved = resolve_profile(
                &config,
                &state,
                &cwd,
                args.provider,
                args.context.as_ref(),
                args.profile.as_ref(),
            )?;
            if !cli.quiet && config.settings.show_run_banner {
                let context = resolved
                    .context
                    .as_ref()
                    .map_or_else(|| "(direct)".to_owned(), ToString::to_string);
                eprintln!(
                    "aictx: context={context} profile={} auth={} billing={} source={}{}",
                    resolved.id,
                    resolved.profile.auth_label(),
                    resolved.profile.billing_domain(),
                    resolved.source.label(),
                    run_identity_hint(&resolved.profile)
                );
            }
            let secrets = SecretManager::new();
            run_profile(
                &config,
                paths,
                &resolved.id,
                &resolved.profile,
                &args.args,
                &secrets,
                &RunOptions {
                    cwd,
                    non_interactive: cli.non_interactive,
                    trusted_runner: args.trusted_runner,
                },
            )
        }
        Some(Command::Status(args)) => execute_status(
            &store,
            paths,
            args.context.as_ref(),
            args.verbose,
            cli.non_interactive,
        ),
        Some(Command::Bind(args)) => {
            let canonical = canonical_directory(&args.path)?;
            store.update_config(|config| {
                if !config.contexts.contains_key(&args.context) {
                    return Err(context_not_found(config, &args.context));
                }
                config.bindings.retain(|binding| binding.path != canonical);
                config.bindings.push(crate::model::Binding {
                    path: canonical.clone(),
                    context: args.context.clone(),
                });
                Ok(())
            })?;
            println!("Bound {} to context {}.", canonical.display(), args.context);
            Ok(0)
        }
        Some(Command::Unbind(args)) => {
            let canonical = binding_lookup_path(&args.path)?;
            let removed = store.update_config(|config| {
                let before = config.bindings.len();
                config.bindings.retain(|binding| binding.path != canonical);
                Ok(before != config.bindings.len())
            })?;
            if !removed {
                return Err(Error::InvalidInput(format!(
                    "no binding exists for {}",
                    canonical.display()
                )));
            }
            println!("Removed binding for {}.", canonical.display());
            Ok(0)
        }
        Some(Command::Bindings) => {
            let config = store.load_config()?;
            if config.bindings.is_empty() {
                println!("No directory bindings configured.");
            } else {
                for binding in &config.bindings {
                    println!("{}\t{}", binding.path.display(), binding.context);
                }
            }
            Ok(0)
        }
        Some(Command::Doctor(args)) => {
            let config = match store.load_config_for_diagnostics() {
                Ok(config) => config,
                Err(error) => {
                    let mut report = doctor::DoctorReport::default();
                    report.push(doctor::CheckLevel::Failure, "metadata", error.to_string());
                    print_doctor_report(&report, args.json)?;
                    return Ok(1);
                }
            };
            let cwd = current_directory()?;
            let mut report = doctor::inspect(&config, paths, &cwd, args.provider);
            append_credential_readiness(
                &mut report,
                &config,
                paths,
                args.provider,
                cli.non_interactive,
            );
            print_doctor_report(&report, args.json)?;
            Ok(i32::from(report.has_failures()))
        }
        Some(Command::Credential(args)) => match args.command {
            CredentialCommand::Check { profile, all } => {
                execute_credential_check(&store, paths, profile.as_ref(), all, cli.non_interactive)
            }
        },
        Some(Command::Env(args)) => {
            let (config, state) = store.load_metadata()?;
            let cwd = current_directory()?;
            let resolved = resolve_context(&config, &state, &cwd, args.context.as_ref())?;
            let context = config
                .contexts
                .get(&resolved.name)
                .ok_or_else(|| Error::ContextNotFound(resolved.name.to_string()))?;
            for line in shell::environment_lines(&config, &resolved.name, context, args.shell) {
                println!("{line}");
            }
            Ok(0)
        }
        Some(Command::ShellInit(args)) => {
            let executable = std::env::current_exe()
                .and_then(|path| path.canonicalize())
                .map_err(|source| {
                    Error::VendorIncompatible(format!(
                        "could not resolve the current aictx executable for shell integration: {source}"
                    ))
                })?;
            println!(
                "{}",
                shell::shell_init(args.shell, &executable, cli.root.as_deref())?
            );
            Ok(0)
        }
        Some(Command::Completions(args)) => {
            shell::generate_completions(args.shell);
            Ok(0)
        }
        Some(Command::Migrate(args)) => execute_migration(cli.root.as_deref(), args.command),
    }
}

fn execute_migration(target_root: Option<&Path>, command: MigrateCommand) -> Result<i32> {
    match command {
        MigrateCommand::Aictx(args) => {
            let (legacy, target) = resolve_migration_paths(target_root, args.from_root.as_deref())?;
            let plan = MigrationPlan::inspect(&legacy, &target)?;
            if args.dry_run {
                println!("Migration plan (dry run; no files were changed).");
                print_migration_paths(&legacy, &target);
                print_migration_summary(plan.summary());
                return Ok(0);
            }

            let receipt = plan.execute()?;
            println!("Copied the aictx store into the ctxlane layout.");
            print_migration_paths(&legacy, &target);
            print_migration_summary(receipt.summary());
            print_safe_path("new config", receipt.config_file());
            print_safe_path("new state", receipt.state_file());
            print_source_preservation_receipt();
            Ok(0)
        }
        MigrateCommand::Recover(args) => {
            let (legacy, target) = resolve_migration_paths(target_root, args.from_root.as_deref())?;
            match recover_incomplete(&legacy, &target)? {
                RecoveryOutcome::NothingToRecover => {
                    println!("No incomplete aictx-to-ctxlane migration was found.");
                }
                RecoveryOutcome::RolledBack => {
                    println!("Rolled back the incomplete aictx-to-ctxlane migration.");
                    print_source_preservation_receipt();
                }
                RecoveryOutcome::Finalized => {
                    println!("Finalized the verified aictx-to-ctxlane migration.");
                    println!("The migrated ctxlane store was kept.");
                    print_source_preservation_receipt();
                }
            }
            Ok(0)
        }
    }
}

fn resolve_migration_paths(
    target_root: Option<&Path>,
    legacy_root: Option<&Path>,
) -> Result<(AppPaths, AppPaths)> {
    if target_root.is_some() && legacy_root.is_none() {
        return Err(Error::InvalidInput(
            "`--from-root <ABSOLUTE_PATH>` is required when global `--root` selects the ctxlane migration target"
                .to_owned(),
        ));
    }
    if let Some(root) = legacy_root {
        validate_from_root(root)?;
    }
    let legacy = AppPaths::discover_for(LEGACY_AICTX, legacy_root)?;
    let target = AppPaths::discover_for(TARGET_CTXLANE, target_root)?;
    Ok((legacy, target))
}

fn validate_from_root(root: &Path) -> Result<()> {
    if !root.is_absolute() {
        return Err(Error::InvalidInput(format!(
            "`--from-root` must be absolute: {}",
            terminal_safe(&root.display().to_string())
        )));
    }
    if root.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(Error::InvalidInput(format!(
            "`--from-root` must not contain `.` or `..` path components: {}",
            terminal_safe(&root.display().to_string())
        )));
    }
    Ok(())
}

fn print_migration_paths(legacy: &AppPaths, target: &AppPaths) {
    print_safe_path("old config", &legacy.config_dir);
    print_safe_path("old data", &legacy.data_dir);
    print_safe_path("old state", &legacy.state_dir);
    print_safe_path("new config", &target.config_dir);
    print_safe_path("new data", &target.data_dir);
    print_safe_path("new state", &target.state_dir);
}

fn print_migration_summary(summary: MigrationSummary) {
    println!("  profiles: {}", summary.profile_count());
    println!("  vendor files: {}", summary.vendor_file_count());
    println!("  vendor directories: {}", summary.vendor_directory_count());
    println!("  skipped lock entries: {}", summary.skipped_lock_count());
}

fn print_safe_path(label: &str, path: &Path) {
    println!("  {label}: {}", terminal_safe(&path.display().to_string()));
}

fn print_source_preservation_receipt() {
    println!("The old aictx store remains available.");
    println!("Its metadata, vendor state, and credentials were not changed.");
}

/// Refuse ordinary startup while a ctxlane migration journal needs recovery.
///
/// This helper is intentionally not active while `aictx` remains the current
/// runtime identity. The ctxlane entry point can call it before loading target
/// metadata after the rename is complete.
pub fn guard_against_incomplete_migration(target: &AppPaths) -> Result<()> {
    let journal = migration_journal_path(target);
    match fs::symlink_metadata(&journal) {
        Ok(_) => Err(Error::PolicyRefused(format!(
            "an incomplete migration journal exists at {}; run `ctxlane migrate recover` before using ctxlane",
            terminal_safe(&journal.display().to_string())
        ))),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::ReadFile {
            path: journal,
            source,
        }),
    }
}

fn execute_init(
    store: &MetadataStore,
    paths: &AppPaths,
    args: &InitArgs,
    non_interactive: bool,
    quiet: bool,
) -> Result<i32> {
    if args.guided {
        return execute_guided_init(store, paths, non_interactive, quiet);
    }

    let created = initialize_store(store)?;
    if !quiet {
        if created {
            print_initialized(paths);
            println!("No credentials were created or imported.");
            println!("Next: add a profile with `aictx profile add --help`.");
        } else {
            println!("aictx is already initialized; existing metadata was left unchanged.");
        }
    }
    Ok(0)
}

fn execute_guided_init(
    store: &MetadataStore,
    paths: &AppPaths,
    non_interactive: bool,
    quiet: bool,
) -> Result<i32> {
    require_interactive_setup_token_terminal(non_interactive, "guided setup")?;

    let created = initialize_store(store)?;
    if !quiet {
        if created {
            print_initialized(paths);
        } else {
            println!("Validated existing aictx metadata; no metadata was overwritten.");
        }
    }

    let (profile_id, secret_reference_is_new) = ensure_guided_claude_profile(store, paths, quiet)?;
    let code = execute_login(
        store,
        paths,
        &LoginArgs {
            profile: profile_id.clone(),
            device: false,
            generate: true,
            trusted_runner: false,
        },
        false,
        secret_reference_is_new,
    )?;
    if code != 0 {
        return Ok(code);
    }

    println!("Guided setup complete.");
    println!("Next: aictx run --profile {profile_id} claude -- -p \"explain this repository\"");
    Ok(0)
}

fn initialize_store(store: &MetadataStore) -> Result<bool> {
    let created = store.initialize()?;
    if created {
        store.update_config(|config| {
            anchor_binaries(config);
            Ok(())
        })?;
    }
    Ok(created)
}

fn print_initialized(paths: &AppPaths) {
    println!("Initialized aictx metadata.");
    println!("  config: {}", paths.config_file.display());
    println!("  state:  {}", paths.state_file.display());
}

fn ensure_guided_claude_profile(
    store: &MetadataStore,
    paths: &AppPaths,
    quiet: bool,
) -> Result<(ProfileId, bool)> {
    let profile_id: ProfileId = "claude:personal".parse()?;
    let config = store.load_config()?;
    if let Some((existing_id, profile)) = config.profiles.iter().find(|(existing_id, _)| {
        existing_id.provider() == profile_id.provider()
            && existing_id
                .name()
                .as_str()
                .eq_ignore_ascii_case(profile_id.name().as_str())
    }) {
        if existing_id != &profile_id {
            return Err(Error::InvalidInput(format!(
                "guided setup requires profile `{profile_id}`, but existing `{existing_id}` conflicts on case-insensitive filesystems"
            )));
        }
        if !matches!(
            profile,
            Profile::Claude {
                auth: ClaudeAuth::SubscriptionToken,
                ..
            }
        ) {
            return Err(Error::InvalidInput(format!(
                "guided setup requires `{profile_id}` to use subscription-token authentication; the existing profile was left unchanged"
            )));
        }
        if !quiet {
            println!("Using existing compatible profile {profile_id}.");
        }
        return Ok((profile_id, false));
    }

    execute_profile(
        store,
        paths,
        ProfileCommand::Add(ProfileAddArgs {
            provider: Provider::Claude,
            name: profile_id.name().clone(),
            auth: AuthArg::Subscription,
            secret_ref: None,
            account: None,
            organization: None,
            workspace: None,
            organization_id: None,
            federation_rule_id: None,
            service_account_id: None,
            identity_token_file: None,
            codex_credential_store: CodexCredentialStore::default(),
        }),
        false,
    )?;
    Ok((profile_id, true))
}

fn terminal_safe(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

fn append_credential_readiness(
    report: &mut doctor::DoctorReport,
    config: &Config,
    paths: &AppPaths,
    provider_filter: Option<Provider>,
    non_interactive: bool,
) {
    let manager = SecretManager::new();
    for (profile_id, profile) in &config.profiles {
        if provider_filter.is_some_and(|filter| filter != profile.provider()) {
            continue;
        }
        let name = format!("{profile_id} credential");
        if non_interactive && profile.requires_static_secret() {
            report.push(
                doctor::CheckLevel::Warning,
                name,
                "not checked because non-interactive mode refuses native keyring reads; run `aictx credential check` from an interactive terminal",
            );
            continue;
        }
        match credential_state(
            config,
            paths,
            profile_id,
            profile,
            &manager,
            non_interactive,
        ) {
            Ok(CredentialState::Available) => report.push(
                doctor::CheckLevel::Pass,
                name,
                "configured authentication material is available",
            ),
            Ok(CredentialState::Unavailable) => report.push(
                doctor::CheckLevel::Failure,
                name,
                format!("authentication material is unavailable; run `aictx login {profile_id}`"),
            ),
            Ok(CredentialState::Unverified)
                if matches!(
                    profile,
                    Profile::Claude {
                        auth: ClaudeAuth::SubscriptionToken | ClaudeAuth::ApiKey,
                        ..
                    }
                ) =>
            {
                report.push(
                    doctor::CheckLevel::Warning,
                    name,
                    "credential is stored and the local Claude auth route matches; remote validity is checked by the first model request",
                );
            }
            Ok(CredentialState::Unverified) => report.push(
                doctor::CheckLevel::Failure,
                name,
                format!(
                    "authentication material could not be verified against the configured identity; run `aictx login {profile_id}`"
                ),
            ),
            Err(error) => report.push(doctor::CheckLevel::Failure, name, error.to_string()),
        }
    }
}

fn print_doctor_report(report: &doctor::DoctorReport, json: bool) -> Result<()> {
    if json {
        let value = serde_json::json!({
            "ok": !report.has_failures(),
            "checks": &report.checks,
        });
        let output = serde_json::to_string_pretty(&value).map_err(|error| {
            Error::InvalidConfig(format!("failed to serialize doctor report: {error}"))
        })?;
        println!("{output}");
    } else {
        for check in &report.checks {
            println!(
                "{:<4} {:<24} {}",
                check.level.label(),
                check.name,
                terminal_safe(&check.detail)
            );
        }
    }
    Ok(())
}

fn execute_profile(
    store: &MetadataStore,
    paths: &AppPaths,
    command: ProfileCommand,
    non_interactive: bool,
) -> Result<i32> {
    match command {
        ProfileCommand::Add(args) => {
            require_initialized(store)?;
            let profile_id = ProfileId::new(args.provider, args.name.clone());
            let state_dir = paths.profile_state_dir(args.provider, &args.name);
            let _profile_lock = acquire_profile_lock(
                &paths.profile_lock(profile_id.provider(), profile_id.name()),
                true,
            )?;
            let mut archived_orphan = None;
            let mut state_prepared = false;
            let update = store.update_config(|config| {
                if let Some(existing) = config.profiles.keys().find(|existing| {
                    existing.provider() == profile_id.provider()
                        && existing
                            .name()
                            .as_str()
                            .eq_ignore_ascii_case(profile_id.name().as_str())
                }) {
                    if existing == &profile_id {
                        return Err(Error::InvalidInput(format!(
                            "profile `{profile_id}` already exists"
                        )));
                    }
                    return Err(Error::InvalidInput(format!(
                        "profile `{profile_id}` conflicts with existing `{existing}` on case-insensitive filesystems"
                    )));
                }
                archived_orphan = archive_managed_profile_state(paths, &profile_id, &state_dir)?;
                state_prepared = true;
                ensure_secure_directory(&state_dir)?;
                let profile = build_profile(&profile_id, &state_dir, &args)?;
                config.profiles.insert(profile_id.clone(), profile);
                Ok(())
            });
            if let Err(error) = update {
                if state_prepared {
                    rollback_failed_profile_add(&state_dir, archived_orphan.as_deref())?;
                }
                return Err(error);
            }
            if let Some(archived) = archived_orphan {
                println!(
                    "Archived orphaned vendor state from an interrupted removal at {}.",
                    archived.display()
                );
            }
            println!("Added profile {profile_id}.");
            Ok(0)
        }
        ProfileCommand::List => {
            let config = store.load_config()?;
            if config.profiles.is_empty() {
                println!("No profiles configured.");
            } else {
                for (id, profile) in &config.profiles {
                    println!(
                        "{id}\t{}\t{}",
                        profile.auth_label(),
                        profile.billing_domain()
                    );
                }
            }
            Ok(0)
        }
        ProfileCommand::Show { profile } => {
            let config = store.load_config()?;
            let value = config
                .profiles
                .get(&profile)
                .ok_or_else(|| profile_not_found(&config, &profile))?;
            print_profile(&profile, value, true, None);
            Ok(0)
        }
        ProfileCommand::Remove {
            profile,
            delete_secret,
        } => {
            require_initialized(store)?;
            let _profile_lock = acquire_profile_lock(
                &paths.profile_lock(profile.provider(), profile.name()),
                true,
            )?;
            let (value, deleted_keyring_secret) = store.update_config(|current| {
                ensure_profile_unreferenced(current, &profile)?;
                let value = current
                    .profiles
                    .get(&profile)
                    .cloned()
                    .ok_or_else(|| profile_not_found(current, &profile))?;
                let deleted_keyring_secret = if delete_secret {
                    if let Some(reference) = value.secret_ref() {
                        let reference: SecretRef = reference.parse()?;
                        SecretManager::new().delete(&reference, non_interactive)?
                    } else {
                        false
                    }
                } else {
                    false
                };
                if current.profiles.remove(&profile).is_none() {
                    return Err(Error::ProfileNotFound(profile.to_string()));
                }
                Ok((value, deleted_keyring_secret))
            })?;

            let archived_state = match detach_profile_state(paths, &profile, &value) {
                Ok(archived) => archived,
                Err(archive_error) => {
                    let restore = store.update_config(|current| {
                        if current.profiles.contains_key(&profile) {
                            return Err(Error::InvalidInput(format!(
                                "cannot restore profile `{profile}` because that name is already configured"
                            )));
                        }
                        current.profiles.insert(profile.clone(), value.clone());
                        Ok(())
                    });
                    if let Err(restore_error) = restore {
                        return Err(Error::PolicyRefused(format!(
                            "profile metadata was removed, vendor state archival failed ({archive_error}), and metadata rollback also failed ({restore_error}); the managed state will be retired before this profile name can be added again"
                        )));
                    }
                    if deleted_keyring_secret {
                        return Err(Error::InvalidConfig(format!(
                            "profile removal was rolled back because vendor state archival failed ({archive_error}); its keyring credential was already deleted and must be stored again"
                        )));
                    }
                    return Err(archive_error);
                }
            };
            if delete_secret {
                if deleted_keyring_secret {
                    println!("Deleted the local keyring credential.");
                } else {
                    println!("No wrapper-held keyring credential was deleted.");
                }
            }
            if let Some(archived) = archived_state {
                println!("Archived isolated vendor state at {}.", archived.display());
            } else if value.state_dir()
                == paths.profile_state_dir(profile.provider(), profile.name())
            {
                println!("No local vendor state needed archiving.");
            } else {
                println!(
                    "Vendor state outside the managed profile path was left unchanged at {}.",
                    value.state_dir().display()
                );
            }
            println!("Removed profile {profile}. Remote credentials were not revoked.");
            let _ = non_interactive;
            Ok(0)
        }
    }
}

fn ensure_profile_unreferenced(config: &Config, profile: &ProfileId) -> Result<()> {
    for (context_name, context) in &config.contexts {
        if context.claude.as_ref() == Some(profile) || context.codex.as_ref() == Some(profile) {
            return Err(Error::InvalidInput(format!(
                "profile `{profile}` is still referenced by context `{context_name}`"
            )));
        }
    }
    Ok(())
}

fn archive_managed_profile_state(
    paths: &AppPaths,
    profile_id: &ProfileId,
    state_dir: &Path,
) -> Result<Option<PathBuf>> {
    let managed = paths.profile_state_dir(profile_id.provider(), profile_id.name());
    if state_dir != managed || !state_dir.exists() {
        return Ok(None);
    }
    ensure_secure_directory(state_dir)?;
    let generation = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let archived = state_dir.with_file_name(format!(
        "{}.retired-{generation:032x}-{:08x}",
        profile_id.name(),
        std::process::id()
    ));
    if archived.exists() {
        return Err(Error::PolicyRefused(format!(
            "refusing to overwrite archived profile state {}",
            archived.display()
        )));
    }
    fs::rename(state_dir, &archived).map_err(|source| Error::WriteFile {
        path: state_dir.to_path_buf(),
        source,
    })?;
    Ok(Some(archived))
}

fn detach_profile_state(
    paths: &AppPaths,
    profile_id: &ProfileId,
    profile: &Profile,
) -> Result<Option<PathBuf>> {
    archive_managed_profile_state(paths, profile_id, profile.state_dir())
}

fn rollback_failed_profile_add(state_dir: &Path, archived: Option<&Path>) -> Result<()> {
    if state_dir.exists() {
        fs::remove_dir(state_dir).map_err(|source| Error::WriteFile {
            path: state_dir.to_path_buf(),
            source,
        })?;
    }
    if let Some(archived) = archived {
        fs::rename(archived, state_dir).map_err(|source| Error::WriteFile {
            path: state_dir.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn execute_context(store: &MetadataStore, command: ContextCommand) -> Result<i32> {
    match command {
        ContextCommand::Add {
            name,
            claude,
            codex,
        } => {
            if claude.is_none() && codex.is_none() {
                return Err(Error::InvalidInput(
                    "context must include --claude, --codex, or both".to_owned(),
                ));
            }
            store.update_config(|config| {
                if config.contexts.contains_key(&name) {
                    return Err(Error::InvalidInput(format!(
                        "context `{name}` already exists"
                    )));
                }
                validate_context_profile(config, claude.as_ref(), Provider::Claude)?;
                validate_context_profile(config, codex.as_ref(), Provider::Codex)?;
                config.contexts.insert(
                    name.clone(),
                    Context {
                        claude: claude.clone(),
                        codex: codex.clone(),
                    },
                );
                if config.default_context.is_none() {
                    config.default_context = Some(name.clone());
                }
                Ok(())
            })?;
            println!("Added context {name}.");
            Ok(0)
        }
        ContextCommand::List => {
            let config = store.load_config()?;
            if config.contexts.is_empty() {
                println!("No contexts configured.");
            } else {
                for (name, context) in &config.contexts {
                    println!(
                        "{}\tclaude={}\tcodex={}",
                        name,
                        context
                            .claude
                            .as_ref()
                            .map_or("-".to_owned(), ToString::to_string),
                        context
                            .codex
                            .as_ref()
                            .map_or("-".to_owned(), ToString::to_string)
                    );
                }
            }
            Ok(0)
        }
        ContextCommand::Show { name } => {
            let config = store.load_config()?;
            let context = config
                .contexts
                .get(&name)
                .ok_or_else(|| context_not_found(&config, &name))?;
            println!("Context: {name}");
            println!(
                "  Claude: {}",
                context
                    .claude
                    .as_ref()
                    .map_or("not configured".to_owned(), ToString::to_string)
            );
            println!(
                "  Codex:  {}",
                context
                    .codex
                    .as_ref()
                    .map_or("not configured".to_owned(), ToString::to_string)
            );
            Ok(0)
        }
        ContextCommand::Remove { name } => {
            store.update_metadata(|config, state| {
                if state.current_context.as_ref() == Some(&name) {
                    return Err(Error::InvalidInput(format!(
                        "context `{name}` is active; use another context first"
                    )));
                }
                if config
                    .bindings
                    .iter()
                    .any(|binding| binding.context == name)
                {
                    return Err(Error::InvalidInput(format!(
                        "context `{name}` is referenced by a directory binding"
                    )));
                }
                if config.contexts.remove(&name).is_none() {
                    return Err(context_not_found(config, &name));
                }
                if config.default_context.as_ref() == Some(&name) {
                    config.default_context = config.contexts.keys().next().cloned();
                }
                Ok(())
            })?;
            println!("Removed context {name}.");
            Ok(0)
        }
    }
}

fn execute_login(
    store: &MetadataStore,
    paths: &AppPaths,
    args: &LoginArgs,
    non_interactive: bool,
    secret_reference_is_new: bool,
) -> Result<i32> {
    require_initialized(store)?;
    let profile_id = &args.profile;
    let device = args.device;
    let generate = args.generate;
    let lifecycle = acquire_profile_lock(
        &paths.profile_lock(profile_id.provider(), profile_id.name()),
        true,
    )?;
    let config = store.load_config()?;
    let profile = config
        .profiles
        .get(profile_id)
        .cloned()
        .ok_or_else(|| profile_not_found(&config, profile_id))?;
    enforce_runner_policy(&profile, non_interactive, args.trusted_runner)?;
    ensure_secure_directory(profile.state_dir())?;
    if profile.provider() == Provider::Codex {
        let cwd = current_directory()?;
        validate_codex_settings(profile.state_dir(), &cwd)?;
    }
    let manager = SecretManager::new();

    match &profile {
        Profile::Claude {
            auth: ClaudeAuth::SubscriptionToken,
            ..
        } => {
            if device {
                return Err(Error::InvalidInput(
                    "--device is supported only for Codex ChatGPT OAuth".to_owned(),
                ));
            }
            if generate {
                require_interactive_setup_token_terminal(non_interactive, "claude setup-token")?;
            }
            confirm_secret_replacement(
                manager,
                profile_id,
                &profile,
                non_interactive,
                secret_reference_is_new,
            )?;
            if generate {
                match generate_claude_setup_token(&config, &profile, &lifecycle) {
                    Ok(0) => {}
                    Ok(code) => {
                        warn_unstored_claude_setup_token();
                        return Ok(code);
                    }
                    Err(error) => return Err(error),
                }
            }
            let store_result = store_or_validate_secret(
                manager,
                profile_id,
                &profile,
                "Claude subscription setup-token",
                non_interactive,
                secret_reference_is_new,
            );
            if let Err(error) = store_result {
                if generate {
                    warn_unstored_claude_setup_token();
                }
                return Err(error);
            }
            println!(
                "Credential stored locally for {profile_id}. Claude checks remote validity on the first model request. This mode supports model requests only; Remote Control, claude.ai connectors, and --bare are unavailable."
            );
            Ok(0)
        }
        Profile::Claude {
            auth: ClaudeAuth::ApiKey,
            ..
        } => {
            if device || generate {
                return Err(Error::InvalidInput(
                    "--device/--generate is not valid for API-key profiles".to_owned(),
                ));
            }
            confirm_secret_replacement(
                manager,
                profile_id,
                &profile,
                non_interactive,
                secret_reference_is_new,
            )?;
            store_or_validate_secret(
                manager,
                profile_id,
                &profile,
                secret_label(profile.provider()),
                non_interactive,
                secret_reference_is_new,
            )?;
            println!(
                "Credential stored locally for {profile_id}. Claude checks remote validity on the first model request; runs will use {} billing.",
                profile.billing_domain()
            );
            Ok(0)
        }
        Profile::Codex {
            auth: CodexAuth::ApiKey,
            ..
        } => {
            if device || generate {
                return Err(Error::InvalidInput(
                    "--device/--generate is not valid for API-key profiles".to_owned(),
                ));
            }
            confirm_secret_replacement(
                manager,
                profile_id,
                &profile,
                non_interactive,
                secret_reference_is_new,
            )?;
            let secret = store_or_validate_secret(
                manager,
                profile_id,
                &profile,
                "OpenAI API key",
                non_interactive,
                secret_reference_is_new,
            )?;
            let code = codex_static_login(
                &config,
                paths,
                profile_id,
                &profile,
                &secret,
                "--with-api-key",
                &lifecycle,
            )?;
            if code == 0 {
                println!(
                    "Credential ready for {profile_id}; Codex vendor login state is initialized for {} billing.",
                    profile.billing_domain()
                );
            }
            Ok(code)
        }
        Profile::Claude {
            auth: ClaudeAuth::Wif,
            wif,
            ..
        } => {
            if device || generate {
                return Err(Error::InvalidInput(
                    "WIF uses an upstream identity-token file, not an interactive login".to_owned(),
                ));
            }
            let path = &wif
                .as_ref()
                .ok_or_else(|| Error::InvalidConfig("missing WIF metadata".to_owned()))?
                .identity_token_file;
            crate::config::validate_sensitive_file(path)?;
            println!(
                "WIF identity source for {profile_id} is available. Anthropic's official client owns token exchange and refresh."
            );
            Ok(0)
        }
        Profile::Codex {
            auth: CodexAuth::ChatgptOauth,
            ..
        } => {
            if generate {
                return Err(Error::InvalidInput(
                    "--generate is valid only for Claude subscription tokens".to_owned(),
                ));
            }
            if non_interactive {
                return Err(Error::InteractionRequired(
                    "Codex browser/device OAuth requires interaction".to_owned(),
                ));
            }
            login_codex(&config, paths, profile_id, &profile, device, &lifecycle)
        }
        Profile::Codex {
            auth: CodexAuth::AccessToken,
            ..
        } => {
            if device || generate {
                return Err(Error::InvalidInput(
                    "--device/--generate is not valid for Codex access tokens".to_owned(),
                ));
            }
            confirm_secret_replacement(
                manager,
                profile_id,
                &profile,
                non_interactive,
                secret_reference_is_new,
            )?;
            let secret = store_or_validate_secret(
                manager,
                profile_id,
                &profile,
                "Codex access token",
                non_interactive,
                secret_reference_is_new,
            )?;
            codex_static_login(
                &config,
                paths,
                profile_id,
                &profile,
                &secret,
                "--with-access-token",
                &lifecycle,
            )
        }
    }
}

fn execute_logout(
    store: &MetadataStore,
    paths: &AppPaths,
    profile_id: &ProfileId,
    non_interactive: bool,
) -> Result<i32> {
    require_initialized(store)?;
    let lifecycle = acquire_profile_lock(
        &paths.profile_lock(profile_id.provider(), profile_id.name()),
        true,
    )?;
    let config = store.load_config()?;
    let profile = config
        .profiles
        .get(profile_id)
        .cloned()
        .ok_or_else(|| profile_not_found(&config, profile_id))?;
    if matches!(
        &profile,
        Profile::Claude {
            auth: ClaudeAuth::Wif,
            ..
        }
    ) {
        return Err(Error::PolicyRefused(
            "logout cannot disable a WIF profile because its identity-token source is external; disable or revoke the upstream identity and remove the profile when appropriate"
                .to_owned(),
        ));
    }
    let reference = profile
        .secret_ref()
        .map(str::parse::<SecretRef>)
        .transpose()?;
    if non_interactive
        && reference
            .as_ref()
            .is_some_and(|reference| matches!(reference, SecretRef::Keyring { .. }))
    {
        return Err(Error::InteractionRequired(
            "deleting an OS-keyring credential may require an unlock or consent prompt".to_owned(),
        ));
    }
    let manager = SecretManager::new();

    let vendor_code = match &profile {
        Profile::Codex {
            auth: CodexAuth::ChatgptOauth | CodexAuth::ApiKey | CodexAuth::AccessToken,
            ..
        } => logout_codex(&config, paths, profile_id, &profile, &lifecycle)?,
        _ => 0,
    };
    if vendor_code != 0 {
        return Ok(vendor_code);
    }

    if let Some(reference) = reference
        && manager.delete(&reference, non_interactive)?
    {
        println!("Deleted wrapper-held keyring credential for {profile_id}.");
    }
    println!(
        "Completed local authentication cleanup for {profile_id}. This does not confirm that local credentials existed or that remote credentials were revoked; use the vendor account controls when revocation is required."
    );
    Ok(0)
}

fn execute_status(
    store: &MetadataStore,
    paths: &AppPaths,
    requested_context: Option<&Name>,
    verbose: bool,
    non_interactive: bool,
) -> Result<i32> {
    let (config, state) = store.load_metadata()?;
    let cwd = current_directory()?;
    let resolved = resolve_context(&config, &state, &cwd, requested_context)?;
    let context = config
        .contexts
        .get(&resolved.name)
        .ok_or_else(|| Error::ContextNotFound(resolved.name.to_string()))?;
    println!("Context: {} ({})", resolved.name, resolved.source.label());
    let manager = SecretManager::new();
    for provider in [Provider::Claude, Provider::Codex] {
        println!();
        println!("{}", title(provider));
        let Some(profile_id) = context.profile(provider) else {
            println!("  profile:        not configured");
            continue;
        };
        let profile = config
            .profiles
            .get(profile_id)
            .ok_or_else(|| profile_not_found(&config, profile_id))?;
        let state = if verbose {
            Some(credential_state(
                &config,
                paths,
                profile_id,
                profile,
                &manager,
                non_interactive,
            )?)
        } else {
            None
        };
        print_profile(profile_id, profile, verbose, state);
    }
    Ok(0)
}

fn execute_credential_check(
    store: &MetadataStore,
    paths: &AppPaths,
    requested: Option<&ProfileId>,
    all: bool,
    non_interactive: bool,
) -> Result<i32> {
    if requested.is_none() && !all {
        return Err(Error::InvalidInput(
            "provide a profile or pass --all".to_owned(),
        ));
    }
    let config = store.load_config()?;
    let manager = SecretManager::new();
    let profiles = if let Some(profile_id) = requested {
        let profile = config
            .profiles
            .get(profile_id)
            .ok_or_else(|| profile_not_found(&config, profile_id))?;
        vec![(profile_id, profile)]
    } else {
        config.profiles.iter().collect()
    };
    let mut exit_code = 0;
    for (profile_id, profile) in profiles {
        let state = credential_state(
            &config,
            paths,
            profile_id,
            profile,
            &manager,
            non_interactive,
        )?;
        println!("{profile_id}: {}", state.label());
        exit_code = match state {
            CredentialState::Available => exit_code,
            CredentialState::Unavailable => exit_code.max(11),
            CredentialState::Unverified => 13,
        };
    }
    Ok(exit_code)
}

fn build_profile(
    profile_id: &ProfileId,
    state_dir: &Path,
    args: &ProfileAddArgs,
) -> Result<Profile> {
    for value in [
        args.account.as_deref(),
        args.organization.as_deref(),
        args.workspace.as_deref(),
        args.organization_id.as_deref(),
        args.federation_rule_id.as_deref(),
        args.service_account_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_metadata(value)?;
    }

    match args.provider {
        Provider::Claude => {
            let auth = match args.auth {
                AuthArg::Subscription | AuthArg::SubscriptionToken => ClaudeAuth::SubscriptionToken,
                AuthArg::ApiKey => ClaudeAuth::ApiKey,
                AuthArg::Wif => ClaudeAuth::Wif,
                AuthArg::ChatgptOauth | AuthArg::AccessToken => {
                    return Err(Error::InvalidInput(format!(
                        "auth mode {:?} is not valid for Claude",
                        args.auth
                    )));
                }
            };
            if (args.workspace.is_some() && auth != ClaudeAuth::Wif)
                || args.codex_credential_store != CodexCredentialStore::default()
            {
                return Err(Error::InvalidInput(
                    "--workspace is valid for Claude only with WIF; Codex credential-store options cannot be used for Claude"
                        .to_owned(),
                ));
            }
            let (secret_ref, wif) = match auth {
                ClaudeAuth::Wif => {
                    if args.secret_ref.is_some() {
                        return Err(Error::InvalidInput(
                            "WIF profiles do not store static secrets".to_owned(),
                        ));
                    }
                    let cwd = current_directory()?;
                    let token_file = absolute_path(
                        args.identity_token_file.as_deref().ok_or_else(|| {
                            Error::InvalidInput("WIF requires --identity-token-file".to_owned())
                        })?,
                        &cwd,
                    );
                    let wif = WifConfig {
                        organization_id: required_option(
                            args.organization_id.as_ref(),
                            "--organization-id",
                        )?,
                        federation_rule_id: required_option(
                            args.federation_rule_id.as_ref(),
                            "--federation-rule-id",
                        )?,
                        service_account_id: required_option(
                            args.service_account_id.as_ref(),
                            "--service-account-id",
                        )?,
                        workspace_id: args.workspace.clone(),
                        identity_token_file: token_file,
                    };
                    (None, Some(wif))
                }
                ClaudeAuth::SubscriptionToken | ClaudeAuth::ApiKey => {
                    reject_wif_options(args)?;
                    (
                        Some(resolve_secret_ref(profile_id, args.secret_ref.as_deref())?),
                        None,
                    )
                }
            };
            Ok(Profile::Claude {
                billing_domain: match auth {
                    ClaudeAuth::SubscriptionToken => BillingDomain::ClaudeSubscription,
                    ClaudeAuth::ApiKey | ClaudeAuth::Wif => BillingDomain::AnthropicApi,
                },
                auth,
                state_dir: state_dir.to_path_buf(),
                secret_ref,
                account_hint: args.account.clone(),
                expected_organization: args.organization.clone(),
                wif,
            })
        }
        Provider::Codex => {
            reject_wif_options(args)?;
            if args.organization.is_some() {
                return Err(Error::InvalidInput(
                    "--organization is a Claude profile option".to_owned(),
                ));
            }
            let auth = match args.auth {
                AuthArg::Subscription | AuthArg::SubscriptionToken | AuthArg::ChatgptOauth => {
                    CodexAuth::ChatgptOauth
                }
                AuthArg::ApiKey => CodexAuth::ApiKey,
                AuthArg::AccessToken => CodexAuth::AccessToken,
                AuthArg::Wif => {
                    return Err(Error::InvalidInput(format!(
                        "auth mode {:?} is not valid for Codex",
                        args.auth
                    )));
                }
            };
            let secret_ref = match auth {
                CodexAuth::ChatgptOauth => {
                    if args.secret_ref.is_some() {
                        return Err(Error::InvalidInput(
                            "ChatGPT OAuth credentials must remain vendor-managed".to_owned(),
                        ));
                    }
                    None
                }
                CodexAuth::ApiKey | CodexAuth::AccessToken => {
                    Some(resolve_secret_ref(profile_id, args.secret_ref.as_deref())?)
                }
            };
            if auth == CodexAuth::AccessToken && args.workspace.as_deref().is_none_or(str::is_empty)
            {
                return Err(Error::InvalidInput(
                    "Codex access-token profiles require --workspace".to_owned(),
                ));
            }
            if auth == CodexAuth::ApiKey && args.workspace.is_some() {
                return Err(Error::InvalidInput(
                    "--workspace is valid for Codex only with ChatGPT OAuth or access-token authentication"
                        .to_owned(),
                ));
            }
            Ok(Profile::Codex {
                billing_domain: match auth {
                    CodexAuth::ApiKey => BillingDomain::OpenaiApi,
                    CodexAuth::ChatgptOauth | CodexAuth::AccessToken => {
                        BillingDomain::ChatgptSubscription
                    }
                },
                auth,
                state_dir: state_dir.to_path_buf(),
                secret_ref,
                account_hint: args.account.clone(),
                expected_workspace_id: args.workspace.clone(),
                credential_store: args.codex_credential_store,
                trusted_runners_only: auth == CodexAuth::AccessToken,
            })
        }
    }
}

fn store_or_validate_secret(
    manager: SecretManager,
    profile_id: &ProfileId,
    profile: &Profile,
    label: &str,
    non_interactive: bool,
    confirm_new_reference_before_write: bool,
) -> Result<SecretString> {
    let reference = parse_profile_secret_ref(profile_id, profile.secret_ref())?;
    if non_interactive {
        return Err(Error::InteractionRequired(
            "writing an OS keyring may require a consent or unlock prompt; run interactively"
                .to_owned(),
        ));
    }
    let secret = if matches!(
        profile,
        Profile::Claude {
            auth: ClaudeAuth::SubscriptionToken,
            ..
        }
    ) {
        prompt_claude_setup_token(label, false)?
    } else {
        prompt_secret(label, false)?
    };
    // Guided profile creation and login use separate metadata transactions. Recheck the new,
    // generation-specific keyring reference while the login lifecycle lock is held so another
    // aictx process cannot populate it in that gap and be overwritten without consent.
    if confirm_new_reference_before_write
        && manager.exists(&reference, false)?
        && !confirm_secret_replacement_prompt(profile_id)?
    {
        return Err(Error::Cancelled);
    }
    manager.put(&reference, &secret)?;
    Ok(secret)
}

fn warn_unstored_claude_setup_token() {
    eprintln!(
        "Warning: Claude Code may have created a remote setup token, but aictx did not store it. Revoke that token in your Claude account settings (Settings > Claude Code) before retrying."
    );
}

fn confirm_secret_replacement(
    manager: SecretManager,
    profile_id: &ProfileId,
    profile: &Profile,
    non_interactive: bool,
    secret_reference_is_new: bool,
) -> Result<()> {
    if non_interactive {
        return Err(Error::InteractionRequired(
            "writing an OS keyring may require a consent or unlock prompt; run interactively"
                .to_owned(),
        ));
    }
    if secret_reference_is_new {
        return Ok(());
    }
    let reference = parse_profile_secret_ref(profile_id, profile.secret_ref())?;
    if !manager.exists(&reference, false)? {
        return Ok(());
    }
    if confirm_secret_replacement_prompt(profile_id)? {
        Ok(())
    } else {
        Err(Error::Cancelled)
    }
}

fn confirm_secret_replacement_prompt(profile_id: &ProfileId) -> Result<bool> {
    confirm(
        &format!(
            "A local credential already exists for {profile_id}. Replacing it does not revoke the old remote credential. Replace it? [y/N] "
        ),
        "credential replacement confirmation requires a terminal; rerun login interactively",
    )
}

fn require_interactive_setup_token_terminal(non_interactive: bool, operation: &str) -> Result<()> {
    if non_interactive || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(Error::InteractionRequired(format!(
            "{operation} requires terminal input and output for the interactive `claude setup-token` flow"
        )));
    }
    Ok(())
}

fn resolve_secret_ref(profile_id: &ProfileId, supplied: Option<&str>) -> Result<String> {
    let reference = if let Some(supplied) = supplied {
        supplied.parse::<SecretRef>()?
    } else {
        SecretRef::default_for(profile_id)
    };
    Ok(reference.to_string())
}

fn validate_context_profile(
    config: &Config,
    profile_id: Option<&ProfileId>,
    provider: Provider,
) -> Result<()> {
    let Some(profile_id) = profile_id else {
        return Ok(());
    };
    if profile_id.provider() != provider {
        return Err(Error::InvalidInput(format!(
            "{provider} slot cannot reference `{profile_id}`"
        )));
    }
    if !config.profiles.contains_key(profile_id) {
        return Err(profile_not_found(config, profile_id));
    }
    Ok(())
}

fn print_profile(
    profile_id: &ProfileId,
    profile: &Profile,
    verbose: bool,
    credential: Option<CredentialState>,
) {
    println!("  profile:        {profile_id}");
    println!("  auth:           {}", profile.auth_label());
    println!("  billing:        {}", profile.billing_domain());
    if let Some(account) = profile.account_hint() {
        println!("  account:        {}", shell::mask_identity(account));
    }
    if let Some(organization) = profile.expected_organization() {
        println!(
            "  organization:   {} (configured, not independently verified)",
            shell::mask_identity(organization)
        );
    }
    if let Some(workspace) = profile.expected_workspace_id() {
        println!(
            "  workspace:      {} (forced in Codex config)",
            shell::mask_identity(workspace)
        );
    }
    if let Profile::Claude {
        auth: ClaudeAuth::Wif,
        wif: Some(wif),
        ..
    } = profile
    {
        println!(
            "  WIF org:        {} (forced selector)",
            shell::mask_identity(&wif.organization_id)
        );
        if let Some(workspace) = &wif.workspace_id {
            println!(
                "  WIF workspace:  {} (forced selector)",
                shell::mask_identity(workspace)
            );
        }
        println!(
            "  service acct:   {} (forced selector)",
            shell::mask_identity(&wif.service_account_id)
        );
    }
    if verbose {
        println!("  state:          {}", profile.state_dir().display());
        if let Some(reference) = profile.secret_ref() {
            println!("  credential:     {reference}");
        } else {
            println!("  credential:     vendor/identity-provider managed");
        }
        if let Some(credential) = credential {
            println!("  availability:   {}", credential.label());
        }
    }
    if matches!(
        profile,
        Profile::Claude {
            auth: ClaudeAuth::SubscriptionToken,
            ..
        }
    ) {
        println!(
            "  warning:        setup-token mode has no Remote Control, claude.ai connectors, or --bare support"
        );
    }
}

fn run_identity_hint(profile: &Profile) -> String {
    let mut hints = Vec::new();
    if let Some(account) = profile.account_hint() {
        hints.push(format!("account={}", shell::mask_identity(account)));
    }
    if let Some(organization) = profile.expected_organization() {
        hints.push(format!(
            "organization={} (configured)",
            shell::mask_identity(organization)
        ));
    }
    if let Some(workspace) = profile.expected_workspace_id() {
        hints.push(format!(
            "workspace={} (forced)",
            shell::mask_identity(workspace)
        ));
    }
    if let Profile::Claude {
        auth: ClaudeAuth::Wif,
        wif: Some(wif),
        ..
    } = profile
    {
        hints.push(format!(
            "wif-org={} (forced)",
            shell::mask_identity(&wif.organization_id)
        ));
        if let Some(workspace) = &wif.workspace_id {
            hints.push(format!(
                "wif-workspace={} (forced)",
                shell::mask_identity(workspace)
            ));
        }
    }
    if hints.is_empty() {
        String::new()
    } else {
        format!(" {}", hints.join(" "))
    }
}

fn print_selection_change(change: &activation::SelectionChange) {
    eprintln!("This changes the account profile used for future runs.");
    eprintln!(
        "Global context: {} -> {}",
        change.previous(),
        change.target()
    );
    for (provider, (previous, target)) in [Provider::Claude, Provider::Codex].into_iter().zip(
        change
            .previous_profiles()
            .iter()
            .zip(change.target_profiles()),
    ) {
        if previous != target {
            eprintln!(
                "  {provider}: {} -> {}",
                profile_selection_summary(previous.as_ref()),
                profile_selection_summary(target.as_ref())
            );
        }
    }
    eprintln!("The selected account or organization may be different.");
}

fn profile_selection_summary(selection: Option<&activation::ProfileSelection>) -> String {
    selection.map_or_else(
        || "none".to_owned(),
        |selection| {
            format!(
                "{} ({}, {})",
                selection.id(),
                selection.auth_label(),
                selection.billing_domain()
            )
        },
    )
}

fn print_activation_receipt(receipt: &activation::ActivationReceipt) {
    println!("Global active context: {}", receipt.global_context());
    println!(
        "Global profiles: {}",
        profile_route_summary(receipt.global_profiles())
    );
    println!(
        "Effective here at commit: {} ({})",
        receipt.effective_context(),
        receipt.source().label()
    );
    println!(
        "Effective profiles: {}",
        profile_route_summary(receipt.effective_profiles())
    );
    if receipt.is_shadowed() {
        println!("The directory binding takes precedence in this directory.");
    }
}

fn profile_route_summary(profiles: &[Option<activation::ProfileSelection>; 2]) -> String {
    [Provider::Claude, Provider::Codex]
        .into_iter()
        .zip(profiles)
        .filter_map(|(provider, profile)| {
            profile
                .as_ref()
                .map(|profile| format!("{provider}={}", profile_selection_summary(Some(profile))))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn reject_wif_options(args: &ProfileAddArgs) -> Result<()> {
    if args.organization_id.is_some()
        || args.federation_rule_id.is_some()
        || args.service_account_id.is_some()
        || args.identity_token_file.is_some()
    {
        return Err(Error::InvalidInput(
            "WIF identity options require --auth wif".to_owned(),
        ));
    }
    Ok(())
}

fn required_option(value: Option<&String>, flag: &str) -> Result<String> {
    value
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| Error::InvalidInput(format!("WIF requires {flag}")))
}

fn validate_metadata(value: &str) -> Result<()> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
    {
        return Err(Error::InvalidInput(
            "profile metadata must be 1-512 trimmed characters and contain no control characters"
                .to_owned(),
        ));
    }
    Ok(())
}

fn require_initialized(store: &MetadataStore) -> Result<()> {
    let config_file = &store.paths().config_file;
    match config_file.try_exists() {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::NotInitialized),
        Err(source) => Err(Error::ReadFile {
            path: config_file.clone(),
            source,
        }),
    }
}

fn absolute_path(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn confirm(prompt: &str, non_terminal_error: &str) -> Result<bool> {
    if !io::stdin().is_terminal() {
        return Err(Error::InteractionRequired(non_terminal_error.to_owned()));
    }
    eprint!("{prompt}");
    io::stderr()
        .flush()
        .map_err(|error| Error::CredentialStore(error.to_string()))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| Error::CredentialStore(error.to_string()))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn anchor_binaries(config: &mut Config) {
    for binary in [&mut config.binaries.claude, &mut config.binaries.codex] {
        if binary.components().count() != 1 {
            continue;
        }
        let Ok(resolved) = which::which(&*binary) else {
            continue;
        };
        let Ok(canonical) = resolved.canonicalize() else {
            continue;
        };
        if is_in_current_repository(&canonical) {
            continue;
        }
        *binary = resolved;
    }
}

const fn title(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => "Claude",
        Provider::Codex => "Codex",
    }
}
