use std::path::PathBuf;

use crate::{
    Error, Result,
    model::{AuthArg, CodexCredentialStore, Config, Name, ProfileId, Provider},
};

use super::{Field, FieldId, NAME_LIMIT, OptionalEdit, PATH_LIMIT};

pub(super) fn context_fields(
    config: &Config,
    name: &str,
    claude: Option<&ProfileId>,
    codex: Option<&ProfileId>,
) -> Vec<Field> {
    let (claude_options, claude_selected) = profile_options(config, Provider::Claude, claude);
    let (codex_options, codex_selected) = profile_options(config, Provider::Codex, codex);
    vec![
        Field::text(FieldId::Name, "Name", name, NAME_LIMIT),
        Field::choice(
            FieldId::Claude,
            "Claude profile",
            claude_options,
            claude_selected,
        ),
        Field::choice(
            FieldId::Codex,
            "Codex profile",
            codex_options,
            codex_selected,
        ),
    ]
}

fn profile_options(
    config: &Config,
    provider: Provider,
    selected: Option<&ProfileId>,
) -> (Vec<String>, usize) {
    let mut values = vec!["(none)".to_owned()];
    values.extend(
        config
            .profiles
            .keys()
            .filter(|id| id.provider() == provider)
            .map(ToString::to_string),
    );
    let selected = selected
        .and_then(|id| values.iter().position(|value| value == &id.to_string()))
        .unwrap_or(0);
    (values, selected)
}

pub(super) fn binding_fields(path: &str, context: Option<&Name>, config: &Config) -> Vec<Field> {
    let contexts = config
        .contexts
        .keys()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let selected = context
        .and_then(|name| contexts.iter().position(|value| value == name.as_str()))
        .unwrap_or(0);
    vec![
        Field::text(FieldId::Path, "Directory path", path, PATH_LIMIT),
        Field::choice(FieldId::Context, "Context", contexts, selected),
    ]
}

pub(super) fn take_or(fields: &[Field], id: FieldId, default: Field) -> Field {
    fields
        .iter()
        .find(|field| field.id == id)
        .cloned()
        .unwrap_or(default)
}

pub(super) fn claude_auth_options() -> Vec<String> {
    ["subscription", "api-key", "wif"]
        .map(str::to_owned)
        .to_vec()
}

pub(super) fn codex_auth_options() -> Vec<String> {
    ["subscription", "api-key", "access-token"]
        .map(str::to_owned)
        .to_vec()
}

pub(super) fn credential_store_options() -> Vec<String> {
    ["file", "keyring", "auto"].map(str::to_owned).to_vec()
}

pub(super) const fn credential_store_index(store: CodexCredentialStore) -> usize {
    match store {
        CodexCredentialStore::File => 0,
        CodexCredentialStore::Keyring => 1,
        CodexCredentialStore::Auto => 2,
    }
}

pub(super) fn parse_credential_store(value: &str) -> Result<CodexCredentialStore> {
    match value {
        "file" => Ok(CodexCredentialStore::File),
        "keyring" => Ok(CodexCredentialStore::Keyring),
        "auto" => Ok(CodexCredentialStore::Auto),
        _ => Err(Error::InvalidInput(format!(
            "unknown Codex credential store `{value}`"
        ))),
    }
}

pub(super) fn parse_provider(value: &str) -> Result<Provider> {
    match value {
        "claude" => Ok(Provider::Claude),
        "codex" => Ok(Provider::Codex),
        _ => Err(Error::InvalidInput(format!("unknown provider `{value}`"))),
    }
}

pub(super) fn parse_auth(value: &str) -> Result<AuthArg> {
    match value {
        "subscription" => Ok(AuthArg::Subscription),
        "api-key" => Ok(AuthArg::ApiKey),
        "wif" => Ok(AuthArg::Wif),
        "access-token" => Ok(AuthArg::AccessToken),
        _ => Err(Error::InvalidInput(format!(
            "unknown authentication mode `{value}`"
        ))),
    }
}

pub(super) fn optional_profile(value: &str) -> Result<Option<ProfileId>> {
    if value == "(none)" {
        Ok(None)
    } else {
        value.parse().map(Some)
    }
}

pub(super) fn optional_text(value: Option<&str>) -> Option<String> {
    value.filter(|value| !value.is_empty()).map(str::to_owned)
}

pub(super) fn optional_edit(value: &str) -> OptionalEdit {
    match value {
        "" => OptionalEdit::Keep,
        "-" => OptionalEdit::Clear,
        value => OptionalEdit::Set(value.to_owned()),
    }
}

pub(super) fn required_path(value: &str) -> Result<PathBuf> {
    if value.is_empty() {
        Err(Error::InvalidInput("path must not be empty".to_owned()))
    } else {
        Ok(PathBuf::from(value))
    }
}

pub(super) const fn set_status(value: bool) -> &'static str {
    if value { "(set)" } else { "(not set)" }
}
