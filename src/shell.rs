use std::{io, path::Path};

use clap::CommandFactory;

use crate::{
    Error, Result,
    cli::{Cli, Shell},
    model::{Config, Context, Name, Provider},
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

#[must_use]
pub fn environment_lines(
    config: &Config,
    context_name: &Name,
    context: &Context,
    shell: Shell,
) -> Vec<String> {
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

    values
        .into_iter()
        .map(|(key, value)| match shell {
            Shell::Bash | Shell::Zsh => format!("export {key}={}", quote_posix(&value)),
            Shell::Fish => format!("set -gx {key} {}", quote_fish(&value)),
            Shell::Powershell => format!("$Env:{key} = {}", quote_powershell(&value)),
        })
        .collect()
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
}
