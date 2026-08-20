use std::{
    fmt,
    io::Write,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use secrecy::{ExposeSecret, SecretString};

use crate::{
    Error, Result,
    model::{ProfileId, Provider},
};

const DEFAULT_KEYRING_SERVICE: &str = "aictx";
const MAX_SECRET_BYTES: usize = 1024 * 1024;
static KEYRING_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretRef {
    Keyring { service: String, account: String },
}

impl SecretRef {
    #[must_use]
    pub fn default_for(profile_id: &ProfileId) -> Self {
        Self::Keyring {
            service: DEFAULT_KEYRING_SERVICE.to_owned(),
            account: format!(
                "{}-{}-{generation:032x}-{:08x}-{counter:016x}",
                profile_id.provider(),
                profile_id.name(),
                std::process::id(),
                generation = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_nanos()),
                counter = KEYRING_GENERATION.fetch_add(1, Ordering::Relaxed),
            ),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::Keyring { service, account } = self;
        write!(formatter, "keyring://{service}/{account}")
    }
}

impl FromStr for SecretRef {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidInput(
                "secret reference contains a forbidden control character".to_owned(),
            ));
        }

        let rest = value.strip_prefix("keyring://").ok_or_else(|| {
            Error::InvalidInput("secret reference must use `keyring://service/account`".to_owned())
        })?;
        let (service, account) = rest.split_once('/').ok_or_else(|| {
            Error::InvalidInput(
                "keyring reference must have the form `keyring://service/account`".to_owned(),
            )
        })?;
        if service.is_empty() || account.is_empty() || account.contains('/') {
            return Err(Error::InvalidInput(
                "keyring service and account must be non-empty path-safe segments".to_owned(),
            ));
        }
        Ok(Self::Keyring {
            service: service.to_owned(),
            account: account.to_owned(),
        })
    }
}

pub trait SecretProvider {
    fn get(&self, reference: &SecretRef, non_interactive: bool) -> Result<SecretString>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecretManager;

impl SecretManager {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn put(&self, reference: &SecretRef, secret: &SecretString) -> Result<()> {
        enforce_secret_size(secret.expose_secret().len())?;
        let SecretRef::Keyring { service, account } = reference;
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        entry
            .set_password(secret.expose_secret())
            .map_err(|error| Error::CredentialStore(error.to_string()))
    }

    pub fn delete(&self, reference: &SecretRef, non_interactive: bool) -> Result<bool> {
        if non_interactive {
            return Err(Error::InteractionRequired(
                "deleting an OS-keyring credential may require an unlock or consent prompt"
                    .to_owned(),
            ));
        }
        let SecretRef::Keyring { service, account } = reference;
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(Error::CredentialStore(error.to_string())),
        }
    }

    pub fn exists(&self, reference: &SecretRef, non_interactive: bool) -> Result<bool> {
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

impl SecretProvider for SecretManager {
    fn get(&self, reference: &SecretRef, non_interactive: bool) -> Result<SecretString> {
        if non_interactive {
            return Err(Error::InteractionRequired(
                "OS keyrings can display an unlock or consent prompt; use WIF or vendor OAuth for non-interactive runs"
                    .to_owned(),
            ));
        }
        let SecretRef::Keyring { service, account } = reference;
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        match entry.get_password() {
            Ok(secret) if secret.is_empty() => Err(Error::CredentialUnavailable {
                profile: format!("keyring account {account}"),
                reason: "stored credential is empty".to_owned(),
            }),
            Ok(secret) => {
                enforce_secret_size(secret.len())?;
                Ok(secret.into())
            }
            Err(keyring::Error::NoEntry) => Err(Error::CredentialUnavailable {
                profile: format!("keyring account {account}"),
                reason: "no credential is stored".to_owned(),
            }),
            Err(error) => Err(Error::CredentialStore(error.to_string())),
        }
    }
}

pub fn parse_profile_secret_ref(profile_id: &ProfileId, value: Option<&str>) -> Result<SecretRef> {
    let value = value.ok_or_else(|| Error::CredentialUnavailable {
        profile: profile_id.to_string(),
        reason: "profile has no secret reference".to_owned(),
    })?;
    value.parse()
}

pub fn prompt_secret(label: &str, non_interactive: bool) -> Result<SecretString> {
    use std::io::{IsTerminal, Read};

    if std::io::stdin().is_terminal() {
        if non_interactive {
            return Err(Error::InteractionRequired(format!(
                "{label} must be supplied on standard input"
            )));
        }
        let secret = rpassword::prompt_password(format!("{label}: "))
            .map_err(|error| Error::CredentialStore(error.to_string()))?;
        if secret.is_empty() {
            return Err(Error::InvalidInput("credential cannot be empty".to_owned()));
        }
        enforce_secret_size(secret.len())?;
        return Ok(secret.into());
    }

    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::CredentialStore(error.to_string()))?;
    enforce_secret_size(bytes.len())?;
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(Error::InvalidInput("credential cannot be empty".to_owned()));
    }
    let secret = String::from_utf8(bytes)
        .map_err(|_| Error::InvalidInput("credential must be valid UTF-8".to_owned()))?;
    Ok(secret.into())
}

fn enforce_secret_size(length: usize) -> Result<()> {
    if length > MAX_SECRET_BYTES {
        return Err(Error::PolicyRefused(
            "credential exceeds the 1 MiB safety limit".to_owned(),
        ));
    }
    Ok(())
}

pub fn write_secret_to_stdin(
    stdin: &mut impl Write,
    secret: &SecretString,
    program: &str,
) -> Result<()> {
    stdin
        .write_all(secret.expose_secret().as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .map_err(|_| Error::CredentialPipe {
            program: program.to_owned(),
        })
}

#[must_use]
pub const fn secret_label(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => "Claude credential",
        Provider::Codex => "Codex credential",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_keyring_references() {
        assert!("keyring://aictx/claude-work".parse::<SecretRef>().is_ok());
        assert!("vault://team/ai-token".parse::<SecretRef>().is_err());
        assert!("command://curl/attacker".parse::<SecretRef>().is_err());
        assert!("keyring://missing-account".parse::<SecretRef>().is_err());
    }

    #[test]
    fn debug_never_exposes_secret() {
        let secret: SecretString = "canary-secret".into();
        assert!(!format!("{secret:?}").contains("canary-secret"));
    }

    #[test]
    fn every_secret_source_uses_the_same_size_limit() {
        assert!(enforce_secret_size(MAX_SECRET_BYTES).is_ok());
        assert!(matches!(
            enforce_secret_size(MAX_SECRET_BYTES + 1),
            Err(Error::PolicyRefused(_))
        ));
    }
}
