use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::{
    Error, Result,
    model::{AuthArg, CodexCredentialStore, Config, Context, Name, Profile, ProfileId, Provider},
};

use super::input::{Choice, FieldValue, TextInput};

mod support;

use support::{
    binding_fields, claude_auth_options, codex_auth_options, context_fields,
    credential_store_index, credential_store_options, optional_edit, optional_profile,
    optional_text, parse_auth, parse_credential_store, parse_provider, required_path, set_status,
    take_or,
};

const NAME_LIMIT: usize = 64;
const METADATA_LIMIT: usize = 512;
const PATH_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FieldId {
    Name,
    Provider,
    Auth,
    Claude,
    Codex,
    Account,
    Organization,
    Workspace,
    OrganizationId,
    FederationRuleId,
    ServiceAccountId,
    IdentityTokenFile,
    CredentialStore,
    Path,
    Context,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Field {
    pub(super) id: FieldId,
    pub(super) label: String,
    pub(super) value: FieldValue,
}

impl Field {
    fn text(id: FieldId, label: impl Into<String>, value: impl Into<String>, limit: usize) -> Self {
        Self {
            id,
            label: label.into(),
            value: FieldValue::Text(TextInput::new(value, limit)),
        }
    }

    fn choice(
        id: FieldId,
        label: impl Into<String>,
        options: Vec<String>,
        selected: usize,
    ) -> Self {
        Self {
            id,
            label: label.into(),
            value: FieldValue::Choice(Choice::new(options, selected)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum FormOperation {
    ContextAdd,
    ContextEdit {
        name: Name,
        expected: Context,
    },
    ContextRename {
        name: Name,
        expected: Context,
    },
    ProfileAdd,
    ProfileEdit {
        id: ProfileId,
        expected: Profile,
    },
    ProfileRename {
        id: ProfileId,
        expected: Profile,
    },
    BindingAdd,
    BindingEdit {
        expected_path: PathBuf,
        expected_context: Name,
    },
}

impl FormOperation {
    pub(super) const fn verb(&self) -> &'static str {
        match self {
            Self::ContextAdd | Self::ProfileAdd | Self::BindingAdd => "Add",
            Self::ContextEdit { .. } | Self::ProfileEdit { .. } | Self::BindingEdit { .. } => {
                "Edit"
            }
            Self::ContextRename { .. } | Self::ProfileRename { .. } => "Rename",
        }
    }

    pub(super) const fn noun(&self) -> &'static str {
        match self {
            Self::ContextAdd | Self::ContextEdit { .. } | Self::ContextRename { .. } => "context",
            Self::ProfileAdd | Self::ProfileEdit { .. } | Self::ProfileRename { .. } => "profile",
            Self::BindingAdd | Self::BindingEdit { .. } => "binding",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OptionalEdit {
    Keep,
    Clear,
    Set(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Submission {
    ContextAdd {
        name: Name,
        context: Context,
    },
    ContextEdit {
        name: Name,
        expected: Context,
        replacement: Context,
    },
    ContextRename {
        name: Name,
        expected: Context,
        replacement: Name,
    },
    ProfileAdd(ProfileDraft),
    ProfileEdit {
        id: ProfileId,
        expected: Profile,
        account: OptionalEdit,
        organization_or_workspace: OptionalEdit,
        credential_store: Option<CodexCredentialStore>,
    },
    ProfileRename {
        id: ProfileId,
        expected: Profile,
        replacement: Name,
    },
    BindingAdd {
        path: PathBuf,
        context: Name,
    },
    BindingEdit {
        expected_path: PathBuf,
        expected_context: Name,
        path: PathBuf,
        context: Name,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProfileDraft {
    pub(super) provider: Provider,
    pub(super) name: Name,
    pub(super) auth: AuthArg,
    pub(super) account: Option<String>,
    pub(super) organization: Option<String>,
    pub(super) workspace: Option<String>,
    pub(super) organization_id: Option<String>,
    pub(super) federation_rule_id: Option<String>,
    pub(super) service_account_id: Option<String>,
    pub(super) identity_token_file: Option<PathBuf>,
    pub(super) credential_store: CodexCredentialStore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FormEvent {
    Changed,
    Submit,
    Cancel,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Form {
    pub(super) operation: FormOperation,
    pub(super) fields: Vec<Field>,
    pub(super) focus: usize,
    pub(super) error: Option<String>,
}

impl Form {
    pub(super) fn context_add(config: &Config) -> Self {
        Self {
            operation: FormOperation::ContextAdd,
            fields: context_fields(config, "", None, None),
            focus: 0,
            error: None,
        }
    }

    pub(super) fn context_edit(name: Name, context: Context, config: &Config) -> Self {
        Self {
            fields: context_fields(config, "", context.claude.as_ref(), context.codex.as_ref())
                .into_iter()
                .filter(|field| field.id != FieldId::Name)
                .collect(),
            operation: FormOperation::ContextEdit {
                name,
                expected: context,
            },
            focus: 0,
            error: None,
        }
    }

    pub(super) fn context_rename(name: Name, context: Context) -> Self {
        Self {
            fields: vec![Field::text(
                FieldId::Name,
                "New name",
                name.as_str(),
                NAME_LIMIT,
            )],
            operation: FormOperation::ContextRename {
                name,
                expected: context,
            },
            focus: 0,
            error: None,
        }
    }

    pub(super) fn profile_add() -> Self {
        let mut form = Self {
            operation: FormOperation::ProfileAdd,
            fields: vec![
                Field::choice(
                    FieldId::Provider,
                    "Provider",
                    vec!["claude".to_owned(), "codex".to_owned()],
                    0,
                ),
                Field::text(FieldId::Name, "Name", "", NAME_LIMIT),
                Field::choice(FieldId::Auth, "Authentication", claude_auth_options(), 0),
            ],
            focus: 0,
            error: None,
        };
        form.rebuild_profile_add_fields();
        form
    }

    pub(super) fn profile_edit(id: ProfileId, profile: Profile) -> Self {
        let account_status = set_status(profile.account_hint().is_some());
        let mut fields = vec![Field::text(
            FieldId::Account,
            format!("Account label {account_status}; blank keeps, - clears"),
            "",
            METADATA_LIMIT,
        )];
        match &profile {
            Profile::Claude {
                expected_organization,
                ..
            } => fields.push(Field::text(
                FieldId::Organization,
                format!(
                    "Expected organization {}; blank keeps, - clears",
                    set_status(expected_organization.is_some())
                ),
                "",
                METADATA_LIMIT,
            )),
            Profile::Codex {
                expected_workspace_id,
                credential_store,
                ..
            } => {
                fields.push(Field::text(
                    FieldId::Workspace,
                    format!(
                        "Expected workspace {}; blank keeps, - clears",
                        set_status(expected_workspace_id.is_some())
                    ),
                    "",
                    METADATA_LIMIT,
                ));
                fields.push(Field::choice(
                    FieldId::CredentialStore,
                    "Codex credential store",
                    credential_store_options(),
                    credential_store_index(*credential_store),
                ));
            }
        }
        Self {
            operation: FormOperation::ProfileEdit {
                id,
                expected: profile,
            },
            fields,
            focus: 0,
            error: None,
        }
    }

    pub(super) fn profile_rename(id: ProfileId, profile: Profile) -> Self {
        Self {
            fields: vec![Field::text(
                FieldId::Name,
                "New name",
                id.name().as_str(),
                NAME_LIMIT,
            )],
            operation: FormOperation::ProfileRename {
                id,
                expected: profile,
            },
            focus: 0,
            error: None,
        }
    }

    pub(super) fn binding_add(cwd: &std::path::Path, config: &Config) -> Self {
        Self {
            operation: FormOperation::BindingAdd,
            fields: binding_fields(cwd.to_string_lossy().as_ref(), None, config),
            focus: 0,
            error: None,
        }
    }

    pub(super) fn binding_edit(
        path: PathBuf,
        context: Name,
        config: &Config,
        focus_path: bool,
    ) -> Self {
        Self {
            fields: binding_fields(path.to_string_lossy().as_ref(), Some(&context), config),
            operation: FormOperation::BindingEdit {
                expected_path: path,
                expected_context: context,
            },
            focus: usize::from(!focus_path),
            error: None,
        }
    }

    pub(super) fn title(&self) -> String {
        format!("{} {}", self.operation.verb(), self.operation.noun())
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> FormEvent {
        self.error = None;
        match key.code {
            KeyCode::Esc => return FormEvent::Cancel,
            KeyCode::Tab => {
                self.focus = (self.focus + 1) % self.fields.len();
                return FormEvent::Changed;
            }
            KeyCode::BackTab => {
                self.focus = self.focus.checked_sub(1).unwrap_or(self.fields.len() - 1);
                return FormEvent::Changed;
            }
            KeyCode::Enter => return FormEvent::Submit,
            _ => {}
        }

        let mut choice_changed = false;
        let Some(field) = self.fields.get_mut(self.focus) else {
            return FormEvent::None;
        };
        match &mut field.value {
            FieldValue::Text(input) => match key.code {
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if let Err(error) = input.insert_char(character) {
                        self.error = Some(error.to_string());
                    }
                }
                KeyCode::Backspace => input.backspace(),
                KeyCode::Delete => input.delete(),
                KeyCode::Left => input.move_left(),
                KeyCode::Right => input.move_right(),
                KeyCode::Home => input.move_home(),
                KeyCode::End => input.move_end(),
                _ => return FormEvent::None,
            },
            FieldValue::Choice(choice) => match key.code {
                KeyCode::Right | KeyCode::Down | KeyCode::Char(' ') => {
                    choice.next();
                    choice_changed = true;
                }
                KeyCode::Left | KeyCode::Up => {
                    choice.previous();
                    choice_changed = true;
                }
                _ => return FormEvent::None,
            },
        }
        if choice_changed
            && matches!(field.id, FieldId::Provider | FieldId::Auth)
            && matches!(self.operation, FormOperation::ProfileAdd)
        {
            self.rebuild_profile_add_fields();
        }
        FormEvent::Changed
    }

    pub(super) fn handle_paste(&mut self, value: &str) {
        self.error = None;
        let Some(Field {
            value: FieldValue::Text(input),
            ..
        }) = self.fields.get_mut(self.focus)
        else {
            return;
        };
        if let Err(error) = input.insert_str(value) {
            self.error = Some(error.to_string());
        }
    }

    pub(super) fn submission(&mut self) -> Option<Submission> {
        match self.build_submission() {
            Ok(submission) => Some(submission),
            Err(error) => {
                self.error = Some(error.to_string());
                None
            }
        }
    }

    fn build_submission(&self) -> Result<Submission> {
        match &self.operation {
            FormOperation::ContextAdd => Ok(Submission::ContextAdd {
                name: Name::parse(self.text(FieldId::Name)?)?,
                context: self.context_value()?,
            }),
            FormOperation::ContextEdit { name, expected } => Ok(Submission::ContextEdit {
                name: name.clone(),
                expected: expected.clone(),
                replacement: self.context_value()?,
            }),
            FormOperation::ContextRename { name, expected } => Ok(Submission::ContextRename {
                name: name.clone(),
                expected: expected.clone(),
                replacement: Name::parse(self.text(FieldId::Name)?)?,
            }),
            FormOperation::ProfileAdd => Ok(Submission::ProfileAdd(self.profile_draft()?)),
            FormOperation::ProfileEdit { id, expected } => Ok(Submission::ProfileEdit {
                id: id.clone(),
                expected: expected.clone(),
                account: optional_edit(self.text(FieldId::Account)?),
                organization_or_workspace: if expected.provider() == Provider::Claude {
                    optional_edit(self.text(FieldId::Organization)?)
                } else {
                    optional_edit(self.text(FieldId::Workspace)?)
                },
                credential_store: if expected.provider() == Provider::Codex {
                    Some(parse_credential_store(
                        self.choice(FieldId::CredentialStore)?,
                    )?)
                } else {
                    None
                },
            }),
            FormOperation::ProfileRename { id, expected } => Ok(Submission::ProfileRename {
                id: id.clone(),
                expected: expected.clone(),
                replacement: Name::parse(self.text(FieldId::Name)?)?,
            }),
            FormOperation::BindingAdd => Ok(Submission::BindingAdd {
                path: required_path(self.text(FieldId::Path)?)?,
                context: Name::parse(self.choice(FieldId::Context)?)?,
            }),
            FormOperation::BindingEdit {
                expected_path,
                expected_context,
            } => Ok(Submission::BindingEdit {
                expected_path: expected_path.clone(),
                expected_context: expected_context.clone(),
                path: required_path(self.text(FieldId::Path)?)?,
                context: Name::parse(self.choice(FieldId::Context)?)?,
            }),
        }
    }

    fn context_value(&self) -> Result<Context> {
        let claude = optional_profile(self.choice(FieldId::Claude)?)?;
        let codex = optional_profile(self.choice(FieldId::Codex)?)?;
        if claude.is_none() && codex.is_none() {
            return Err(Error::InvalidInput(
                "context must select Claude, Codex, or both".to_owned(),
            ));
        }
        Ok(Context { claude, codex })
    }

    fn profile_draft(&self) -> Result<ProfileDraft> {
        let provider = parse_provider(self.choice(FieldId::Provider)?)?;
        let auth = parse_auth(self.choice(FieldId::Auth)?)?;
        let identity_token_file = self
            .text_optional(FieldId::IdentityTokenFile)
            .map(required_path)
            .transpose()?;
        Ok(ProfileDraft {
            provider,
            name: Name::parse(self.text(FieldId::Name)?)?,
            auth,
            account: optional_text(self.text_optional(FieldId::Account)),
            organization: optional_text(self.text_optional(FieldId::Organization)),
            workspace: optional_text(self.text_optional(FieldId::Workspace)),
            organization_id: optional_text(self.text_optional(FieldId::OrganizationId)),
            federation_rule_id: optional_text(self.text_optional(FieldId::FederationRuleId)),
            service_account_id: optional_text(self.text_optional(FieldId::ServiceAccountId)),
            identity_token_file,
            credential_store: self
                .choice_optional(FieldId::CredentialStore)
                .map(parse_credential_store)
                .transpose()?
                .unwrap_or_default(),
        })
    }

    fn text(&self, id: FieldId) -> Result<&str> {
        self.text_optional(id)
            .ok_or_else(|| Error::InvalidInput(format!("missing form field {id:?}")))
    }

    fn text_optional(&self, id: FieldId) -> Option<&str> {
        self.fields.iter().find_map(|field| {
            (field.id == id).then_some(&field.value).and_then(|value| {
                if let FieldValue::Text(input) = value {
                    Some(input.value())
                } else {
                    None
                }
            })
        })
    }

    fn choice(&self, id: FieldId) -> Result<&str> {
        self.choice_optional(id)
            .ok_or_else(|| Error::InvalidInput(format!("missing form field {id:?}")))
    }

    fn choice_optional(&self, id: FieldId) -> Option<&str> {
        self.fields.iter().find_map(|field| {
            (field.id == id).then_some(&field.value).and_then(|value| {
                if let FieldValue::Choice(choice) = value {
                    Some(choice.value())
                } else {
                    None
                }
            })
        })
    }

    fn rebuild_profile_add_fields(&mut self) {
        let provider = self
            .choice_optional(FieldId::Provider)
            .and_then(|value| parse_provider(value).ok())
            .unwrap_or(Provider::Claude);
        let old_auth = self.choice_optional(FieldId::Auth).map(str::to_owned);
        let old = std::mem::take(&mut self.fields);
        let mut fields = Vec::new();
        fields.push(take_or(
            &old,
            FieldId::Provider,
            Field::choice(
                FieldId::Provider,
                "Provider",
                vec!["claude".to_owned(), "codex".to_owned()],
                usize::from(provider == Provider::Codex),
            ),
        ));
        fields.push(take_or(
            &old,
            FieldId::Name,
            Field::text(FieldId::Name, "Name", "", NAME_LIMIT),
        ));
        let auth_options = if provider == Provider::Claude {
            claude_auth_options()
        } else {
            codex_auth_options()
        };
        let auth_index = old_auth
            .as_ref()
            .and_then(|value| auth_options.iter().position(|option| option == value))
            .unwrap_or(0);
        fields.push(Field::choice(
            FieldId::Auth,
            "Authentication",
            auth_options,
            auth_index,
        ));
        fields.push(take_or(
            &old,
            FieldId::Account,
            Field::text(
                FieldId::Account,
                "Account label (optional)",
                "",
                METADATA_LIMIT,
            ),
        ));
        let auth = fields
            .iter()
            .find_map(|field| match &field.value {
                FieldValue::Choice(choice) if field.id == FieldId::Auth => Some(choice.value()),
                _ => None,
            })
            .unwrap_or("subscription");
        match (provider, auth) {
            (Provider::Claude, "wif") => {
                fields.extend([
                    take_or(
                        &old,
                        FieldId::Organization,
                        Field::text(
                            FieldId::Organization,
                            "Expected organization (optional)",
                            "",
                            METADATA_LIMIT,
                        ),
                    ),
                    take_or(
                        &old,
                        FieldId::OrganizationId,
                        Field::text(
                            FieldId::OrganizationId,
                            "WIF organization ID",
                            "",
                            METADATA_LIMIT,
                        ),
                    ),
                    take_or(
                        &old,
                        FieldId::FederationRuleId,
                        Field::text(
                            FieldId::FederationRuleId,
                            "WIF federation rule ID",
                            "",
                            METADATA_LIMIT,
                        ),
                    ),
                    take_or(
                        &old,
                        FieldId::ServiceAccountId,
                        Field::text(
                            FieldId::ServiceAccountId,
                            "WIF service account ID",
                            "",
                            METADATA_LIMIT,
                        ),
                    ),
                    take_or(
                        &old,
                        FieldId::Workspace,
                        Field::text(
                            FieldId::Workspace,
                            "WIF workspace ID (optional)",
                            "",
                            METADATA_LIMIT,
                        ),
                    ),
                    take_or(
                        &old,
                        FieldId::IdentityTokenFile,
                        Field::text(
                            FieldId::IdentityTokenFile,
                            "Identity-token file",
                            "",
                            PATH_LIMIT,
                        ),
                    ),
                ]);
            }
            (Provider::Claude, _) => fields.push(take_or(
                &old,
                FieldId::Organization,
                Field::text(
                    FieldId::Organization,
                    "Expected organization (optional)",
                    "",
                    METADATA_LIMIT,
                ),
            )),
            (Provider::Codex, selected_auth) => {
                if selected_auth != "api-key" {
                    fields.push(take_or(
                        &old,
                        FieldId::Workspace,
                        Field::text(
                            FieldId::Workspace,
                            if selected_auth == "access-token" {
                                "Workspace ID (required)"
                            } else {
                                "Expected workspace (optional)"
                            },
                            "",
                            METADATA_LIMIT,
                        ),
                    ));
                }
                fields.push(take_or(
                    &old,
                    FieldId::CredentialStore,
                    Field::choice(
                        FieldId::CredentialStore,
                        "Codex credential store",
                        credential_store_options(),
                        0,
                    ),
                ));
            }
        }
        self.fields = fields;
        self.focus = self.focus.min(self.fields.len().saturating_sub(1));
    }
}

#[cfg(test)]
mod tests;
