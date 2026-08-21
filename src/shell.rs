use std::{io, path::Path};

use clap::CommandFactory;

use crate::{
    Error, Result,
    cli::{Cli, Shell},
    model::{CodexAuth, Config, Context, Name, Profile, Provider},
};

#[must_use]
pub fn mask_identity(value: &str) -> String {
    if let Some((local, domain)) = value.split_once('@') {
        let first = local.chars().next().unwrap_or('*');
        return format!("{first}***@{domain}");
    }
    let suffix = value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    if value.chars().count() <= 4 {
        "****".to_owned()
    } else {
        format!("***{suffix}")
    }
}

pub fn shell_init(shell: Shell, executable: &Path, root: Option<&Path>) -> Result<String> {
    let executable = executable.to_str().ok_or_else(|| {
        Error::InvalidConfig(format!(
            "shell integration requires a UTF-8 ctxlane executable path: {}",
            executable.display()
        ))
    })?;
    let root = root
        .map(|path| {
            path.to_str().ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "shell integration requires a UTF-8 application root: {}",
                    path.display()
                ))
            })
        })
        .transpose()?;
    Ok(match shell {
        Shell::Bash | Shell::Zsh => {
            let root = root
                .map(|path| format!(" --root {}", quote_posix(path)))
                .unwrap_or_default();
            format!(
                r#"claude() {{
  command {}{} run claude -- "$@"
}}
codex() {{
  command {}{} run codex -- "$@"
}}"#,
                quote_posix(executable),
                root,
                quote_posix(executable),
                root
            )
        }
        Shell::Fish => {
            let root = root
                .map(|path| format!(" --root {}", quote_fish(path)))
                .unwrap_or_default();
            format!(
                r"function claude
    command {}{} run claude -- $argv
end
function codex
    command {}{} run codex -- $argv
end",
                quote_fish(executable),
                root,
                quote_fish(executable),
                root
            )
        }
        Shell::Powershell => {
            let root = root
                .map(|path| format!(" --root {}", quote_powershell(path)))
                .unwrap_or_default();
            format!(
                r"function claude {{
    & {}{} run claude -- @args
}}
function codex {{
    & {}{} run codex -- @args
}}",
                quote_powershell(executable),
                root,
                quote_powershell(executable),
                root
            )
        }
    })
}

pub fn environment_lines(
    config: &Config,
    context_name: &Name,
    context: &Context,
    shell: Shell,
) -> Result<Vec<String>> {
    if context
        .profile(Provider::Codex)
        .and_then(|profile_id| config.profiles.get(profile_id))
        .is_some_and(|profile| {
            matches!(
                profile,
                Profile::Codex {
                    auth: CodexAuth::Wif,
                    ..
                }
            )
        })
    {
        return Err(Error::VendorIncompatible(
            "Codex WIF enrollment is configured, but environment export is unavailable until native runtime qualification is enabled"
                .to_owned(),
        ));
    }
    let mut values = vec![("CTXLANE_CONTEXT", context_name.to_string())];
    if let Some(profile_id) = context.profile(Provider::Claude)
        && let Some(profile) = config.profiles.get(profile_id)
    {
        values.push((
            "CLAUDE_CONFIG_DIR",
            profile.state_dir().display().to_string(),
        ));
    }
    if let Some(profile_id) = context.profile(Provider::Codex)
        && let Some(profile) = config.profiles.get(profile_id)
    {
        values.push(("CODEX_HOME", profile.state_dir().display().to_string()));
    }

    Ok(values
        .into_iter()
        .map(|(key, value)| match shell {
            Shell::Bash | Shell::Zsh => format!("export {key}={}", quote_posix(&value)),
            Shell::Fish => format!("set -gx {key} {}", quote_fish(&value)),
            Shell::Powershell => format!("$Env:{key} = {}", quote_powershell(&value)),
        })
        .collect())
}

pub fn generate_completions(shell: clap_complete::Shell) {
    let mut command = Cli::command();
    clap_complete::generate(shell, &mut command, "ctxlane", &mut io::stdout());
}

fn quote_posix(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn quote_fish(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn quote_powershell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::model::{
        AutomationPolicy, BillingDomain, CodexCredentialStore, CodexWifConfig, ProfileId,
        ProfileUid,
    };

    use super::*;

    #[test]
    fn masks_emails_and_ids() {
        assert_eq!(
            mask_identity("miki@company.example"),
            "m***@company.example"
        );
        assert_eq!(mask_identity("ws_12345678"), "***5678");
        assert_eq!(mask_identity("tiny"), "****");
    }

    #[test]
    fn shell_quoting_does_not_interpolate() {
        assert_eq!(quote_posix("a'b"), "'a'\\''b'");
        assert_eq!(quote_powershell("a'b"), "'a''b'");
        let init = shell_init(Shell::Bash, Path::new("/trusted/ctxlane"), None)
            .unwrap_or_else(|error| panic!("render shell integration: {error}"));
        assert!(init.contains("command '/trusted/ctxlane' run claude"));
        assert!(!init.contains("command ctxlane"));
    }

    #[test]
    fn shell_init_preserves_explicit_root() {
        let init = shell_init(
            Shell::Bash,
            Path::new("/trusted/ctxlane"),
            Some(Path::new("/safe/root's state")),
        )
        .unwrap_or_else(|error| panic!("render shell integration: {error}"));
        assert!(
            init.contains("command '/trusted/ctxlane' --root '/safe/root'\\''s state' run claude")
        );

        let powershell = shell_init(
            Shell::Powershell,
            Path::new("C:/trusted/ctxlane.exe"),
            Some(Path::new("C:/safe/root's state")),
        )
        .unwrap_or_else(|error| panic!("render PowerShell integration: {error}"));
        assert!(
            powershell
                .contains("& 'C:/trusted/ctxlane.exe' --root 'C:/safe/root''s state' run codex")
        );
    }

    #[test]
    fn environment_export_refuses_unqualified_codex_wif() {
        let profile_id: ProfileId = "codex:factory"
            .parse()
            .unwrap_or_else(|error| panic!("profile ID: {error}"));
        let profile = Profile::Codex {
            profile_uid: ProfileUid::parse("profile_00000000000000000000000001")
                .unwrap_or_else(|error| panic!("profile UID: {error}")),
            billing_domain: BillingDomain::ChatgptSubscription,
            auth: CodexAuth::Wif,
            state_dir: "/private/CREDENTIAL_CANARY_state".into(),
            secret_ref: None,
            account_hint: None,
            expected_workspace_id: None,
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: false,
            wif: Some(CodexWifConfig {
                federation_rule_id: "idpm_CREDENTIAL_CANARY_rule".to_owned(),
                identity_token_file: "/private/CREDENTIAL_CANARY_token".into(),
                expected_workspace: "chatgpt-workspace:CREDENTIAL_CANARY".to_owned(),
                expected_principal: "service-account:CREDENTIAL_CANARY".to_owned(),
                allowed_environments: BTreeSet::from(["local-development".to_owned()]),
                allowed_workload_labels: BTreeMap::new(),
                workload_identity_context: None,
                minimum_codex_version: "0.148.0".to_owned(),
            }),
            automation: AutomationPolicy::default(),
        };
        let mut config = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
        config.profiles.insert(profile_id.clone(), profile);
        let context = Context {
            claude: None,
            codex: Some(profile_id),
        };
        let name = Name::parse("factory").unwrap_or_else(|error| panic!("name: {error}"));
        let Err(error) = environment_lines(&config, &name, &context, Shell::Bash) else {
            panic!("Codex WIF environment export must fail");
        };
        assert!(matches!(error, Error::VendorIncompatible(_)));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("CREDENTIAL_CANARY"));
    }
}
