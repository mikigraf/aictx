use std::path::PathBuf;

use crate::{
    Error, Result,
    config::MetadataStore,
    management::{self, ClaudeProfileEdit, CodexProfileEdit, ProfileEdit, ValueEdit},
    model::{Binding, ClaudeAuth, CodexAuth, Name, ProfileId, Provider, WifConfig},
};

use super::{
    App, MessageLevel, Removal,
    editor::{self, Submission},
};

pub(super) fn apply_submission(
    app: &mut App,
    store: &MetadataStore,
    submission: Submission,
) -> Result<()> {
    match submission {
        Submission::ContextAdd { name, context } => {
            let receipt = management::add_context(store, name, context)?;
            finish_mutation(
                app,
                store,
                SelectionTarget::Context(receipt.name.clone()),
                format!("Added context {}.", receipt.name),
            );
        }
        Submission::ContextEdit {
            name,
            expected,
            replacement,
        } => {
            let receipt = management::edit_context(store, &name, &expected, replacement)?;
            finish_mutation(
                app,
                store,
                SelectionTarget::Context(receipt.name.clone()),
                format!("Updated context {}.", receipt.name),
            );
        }
        Submission::ContextRename {
            name,
            expected,
            replacement,
        } => {
            let receipt = management::rename_context(store, &name, replacement, &expected)?;
            finish_mutation(
                app,
                store,
                SelectionTarget::Context(receipt.name.clone()),
                format!("Renamed context {name} to {}.", receipt.name),
            );
        }
        Submission::ProfileAdd(draft) => {
            let next_step = profile_login_step(&draft);
            let draft = management_profile_draft(draft, &app.cwd)?;
            let receipt = management::add_profile(store, draft)?;
            finish_mutation(
                app,
                store,
                SelectionTarget::Profile(receipt.id.clone()),
                format!("Added profile {}. {next_step}", receipt.id),
            );
        }
        Submission::ProfileEdit {
            id,
            expected,
            account,
            organization_or_workspace,
            credential_store,
        } => {
            let edit = match expected.provider() {
                Provider::Claude => ProfileEdit::Claude(ClaudeProfileEdit {
                    account_hint: value_edit(account),
                    expected_organization: value_edit(organization_or_workspace),
                }),
                Provider::Codex => ProfileEdit::Codex(CodexProfileEdit {
                    account_hint: value_edit(account),
                    expected_workspace_id: value_edit(organization_or_workspace),
                    credential_store,
                    trusted_runners_only: None,
                }),
            };
            let receipt = management::edit_profile(store, &id, &expected, edit)?;
            finish_mutation(
                app,
                store,
                SelectionTarget::Profile(receipt.id.clone()),
                format!("Updated profile {}.", receipt.id),
            );
        }
        Submission::ProfileRename {
            id,
            expected,
            replacement,
        } => {
            let receipt = management::rename_profile(store, &id, replacement, &expected)?;
            finish_mutation(
                app,
                store,
                SelectionTarget::Profile(receipt.id.clone()),
                format!("Renamed profile {id} to {}.", receipt.id),
            );
        }
        Submission::BindingAdd { path, context } => {
            let path = resolve_form_path(&app.cwd, path);
            let receipt = management::add_binding(store, &path, context)?;
            let message = format!(
                "Bound {} to context {}.",
                receipt.binding.path.display(),
                receipt.binding.context
            );
            finish_mutation(
                app,
                store,
                SelectionTarget::Binding(receipt.binding.path),
                message,
            );
        }
        Submission::BindingEdit {
            expected_path,
            expected_context,
            path,
            context,
        } => {
            let expected = Binding {
                path: expected_path,
                context: expected_context,
            };
            let path = resolve_form_path(&app.cwd, path);
            let receipt = management::edit_binding(store, &expected, &path, context)?;
            let message = format!(
                "Updated binding {} -> {}.",
                receipt.binding.path.display(),
                receipt.binding.context
            );
            finish_mutation(
                app,
                store,
                SelectionTarget::Binding(receipt.binding.path),
                message,
            );
        }
    }
    Ok(())
}

pub(super) fn apply_removal(app: &mut App, store: &MetadataStore, removal: &Removal) -> Result<()> {
    let message = match removal {
        Removal::Context { name, expected } => {
            let receipt = management::remove_context(store, name, expected)?;
            format!("Removed context {}.", receipt.name)
        }
        Removal::Profile { id, expected } => {
            let receipt = management::remove_profile(store, id, expected)?;
            if let Some(path) = receipt.detached_state {
                format!(
                    "Removed profile {}. Vendor state retained at {}; keyring and remote credentials were retained.",
                    receipt.id,
                    path.display()
                )
            } else {
                format!(
                    "Removed profile {}. Keyring and remote credentials were retained.",
                    receipt.id
                )
            }
        }
        Removal::Binding { expected } => {
            let receipt = management::remove_binding(store, expected)?;
            format!("Removed binding for {}.", receipt.binding.path.display())
        }
    };
    finish_mutation(app, store, SelectionTarget::None, message);
    Ok(())
}

enum SelectionTarget {
    Context(Name),
    Profile(ProfileId),
    Binding(PathBuf),
    None,
}

fn finish_mutation(app: &mut App, store: &MetadataStore, target: SelectionTarget, message: String) {
    match app.reload(store) {
        Ok(()) => {
            match target {
                SelectionTarget::Context(name) => {
                    if let Some(index) = app.config.contexts.keys().position(|value| value == &name)
                    {
                        app.context_index = index;
                    }
                }
                SelectionTarget::Profile(id) => {
                    if let Some(index) = app.config.profiles.keys().position(|value| value == &id) {
                        app.profile_index = index;
                    }
                }
                SelectionTarget::Binding(path) => {
                    if let Some(index) = app
                        .config
                        .bindings
                        .iter()
                        .position(|binding| binding.path == path)
                    {
                        app.binding_index = index;
                    }
                }
                SelectionTarget::None => app.clamp_selections(),
            }
            app.set_message(MessageLevel::Info, message);
        }
        Err(error) => app.set_message(
            MessageLevel::Error,
            format!("The change was saved, but the dashboard could not reload it: {error}"),
        ),
    }
}

fn management_profile_draft(
    draft: editor::ProfileDraft,
    cwd: &std::path::Path,
) -> Result<management::ProfileDraft> {
    match (draft.provider, draft.auth) {
        (Provider::Claude, crate::model::AuthArg::Subscription) => {
            Ok(management::ProfileDraft::Claude {
                name: draft.name,
                auth: ClaudeAuth::SubscriptionToken,
                secret_ref: None,
                account_hint: draft.account,
                expected_organization: draft.organization,
                wif: None,
            })
        }
        (Provider::Claude, crate::model::AuthArg::ApiKey) => Ok(management::ProfileDraft::Claude {
            name: draft.name,
            auth: ClaudeAuth::ApiKey,
            secret_ref: None,
            account_hint: draft.account,
            expected_organization: draft.organization,
            wif: None,
        }),
        (Provider::Claude, crate::model::AuthArg::Wif) => {
            let identity_token_file = draft.identity_token_file.ok_or_else(|| {
                Error::InvalidInput("WIF requires an identity-token file".to_owned())
            })?;
            Ok(management::ProfileDraft::Claude {
                name: draft.name,
                auth: ClaudeAuth::Wif,
                secret_ref: None,
                account_hint: draft.account,
                expected_organization: draft.organization,
                wif: Some(WifConfig {
                    organization_id: required_form_value(
                        draft.organization_id,
                        "WIF organization ID",
                    )?,
                    federation_rule_id: required_form_value(
                        draft.federation_rule_id,
                        "WIF federation rule ID",
                    )?,
                    service_account_id: required_form_value(
                        draft.service_account_id,
                        "WIF service account ID",
                    )?,
                    workspace_id: draft.workspace,
                    identity_token_file: resolve_form_path(cwd, identity_token_file),
                }),
            })
        }
        (Provider::Codex, crate::model::AuthArg::Subscription) => {
            Ok(management::ProfileDraft::Codex {
                name: draft.name,
                auth: CodexAuth::ChatgptOauth,
                secret_ref: None,
                account_hint: draft.account,
                expected_workspace_id: draft.workspace,
                credential_store: draft.credential_store,
                trusted_runners_only: false,
            })
        }
        (Provider::Codex, crate::model::AuthArg::ApiKey) => Ok(management::ProfileDraft::Codex {
            name: draft.name,
            auth: CodexAuth::ApiKey,
            secret_ref: None,
            account_hint: draft.account,
            expected_workspace_id: None,
            credential_store: draft.credential_store,
            trusted_runners_only: false,
        }),
        (Provider::Codex, crate::model::AuthArg::AccessToken) => {
            Ok(management::ProfileDraft::Codex {
                name: draft.name,
                auth: CodexAuth::AccessToken,
                secret_ref: None,
                account_hint: draft.account,
                expected_workspace_id: Some(required_form_value(draft.workspace, "workspace ID")?),
                credential_store: draft.credential_store,
                trusted_runners_only: true,
            })
        }
        _ => Err(Error::InvalidInput(
            "authentication mode does not match the selected provider".to_owned(),
        )),
    }
}

fn value_edit(value: editor::OptionalEdit) -> ValueEdit<String> {
    match value {
        editor::OptionalEdit::Keep => ValueEdit::Keep,
        editor::OptionalEdit::Clear => ValueEdit::Clear,
        editor::OptionalEdit::Set(value) => ValueEdit::Set(value),
    }
}

fn required_form_value(value: Option<String>, label: &str) -> Result<String> {
    value.ok_or_else(|| Error::InvalidInput(format!("{label} is required")))
}

fn resolve_form_path(cwd: &std::path::Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn profile_login_step(draft: &editor::ProfileDraft) -> String {
    let id = ProfileId::new(draft.provider, draft.name.clone());
    match (draft.provider, draft.auth) {
        (Provider::Claude, crate::model::AuthArg::Subscription) => {
            format!("Next: ctxlane login {id} --generate")
        }
        (Provider::Claude, crate::model::AuthArg::Wif) => {
            "The external WIF route is ready; no credential was stored.".to_owned()
        }
        _ => format!("Next: ctxlane login {id}"),
    }
}
