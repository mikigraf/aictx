use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::model::{
    AutomationPolicy, BillingDomain, CodexAuth, CodexCredentialStore, Profile, ProfileId,
    ProfileUid,
};

use super::{FieldId, Form, FormEvent, OptionalEdit, Submission};

fn uid() -> ProfileUid {
    ProfileUid::parse("profile_00000000000000000000000001")
        .unwrap_or_else(|error| panic!("profile UID: {error}"))
}

#[test]
fn profile_add_exposes_every_supported_auth_shape() {
    let mut form = Form::profile_add();
    assert_eq!(
        form.choice(FieldId::Auth)
            .unwrap_or_else(|error| panic!("auth: {error}")),
        "subscription"
    );
    form.focus = 2;
    let _ = form.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    assert_eq!(
        form.choice(FieldId::Auth)
            .unwrap_or_else(|error| panic!("auth: {error}")),
        "wif"
    );
    assert!(form.text_optional(FieldId::Organization).is_some());
    assert!(form.text_optional(FieldId::OrganizationId).is_some());
    assert!(form.text_optional(FieldId::IdentityTokenFile).is_some());

    form.focus = 0;
    let _ = form.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(
        form.choice(FieldId::Provider)
            .unwrap_or_else(|error| panic!("provider: {error}")),
        "codex"
    );
    assert_eq!(
        form.choice(FieldId::Auth)
            .unwrap_or_else(|error| panic!("auth: {error}")),
        "subscription"
    );
    assert!(form.choice_optional(FieldId::CredentialStore).is_some());
    form.focus = 2;
    let _ = form.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    assert_eq!(
        form.choice(FieldId::Auth)
            .unwrap_or_else(|error| panic!("auth: {error}")),
        "access-token"
    );
    assert!(form.text_optional(FieldId::Workspace).is_some());
}

#[test]
fn profile_edit_does_not_prefill_persisted_identity_metadata() {
    let id: ProfileId = "claude:work"
        .parse()
        .unwrap_or_else(|error| panic!("profile: {error}"));
    let profile = Profile::Claude {
        profile_uid: uid(),
        billing_domain: BillingDomain::AnthropicApi,
        auth: crate::model::ClaudeAuth::ApiKey,
        state_dir: PathBuf::from("/private/state"),
        secret_ref: Some("keyring://private/secret".to_owned()),
        account_hint: Some("person@example.test".to_owned()),
        expected_organization: Some("private-org".to_owned()),
        wif: None,
        automation: AutomationPolicy::default(),
    };
    let form = Form::profile_edit(id, profile);
    assert_eq!(
        form.text(FieldId::Account)
            .unwrap_or_else(|error| panic!("account: {error}")),
        ""
    );
    assert_eq!(
        form.text(FieldId::Organization)
            .unwrap_or_else(|error| panic!("organization: {error}")),
        ""
    );
    let rendered = format!("{:?}", form.fields);
    assert!(!rendered.contains("person@example.test"));
    assert!(!rendered.contains("private-org"));
    assert!(!rendered.contains("keyring://"));
    assert!(rendered.contains("(set)"));
}

#[test]
fn codex_wif_edit_hides_inapplicable_workspace_and_credential_store() {
    let id: ProfileId = "codex:factory"
        .parse()
        .unwrap_or_else(|error| panic!("profile: {error}"));
    let profile = Profile::Codex {
        profile_uid: uid(),
        billing_domain: BillingDomain::ChatgptSubscription,
        auth: CodexAuth::Wif,
        state_dir: PathBuf::from("/private/codex-wif-state"),
        secret_ref: None,
        account_hint: Some("private-account".to_owned()),
        expected_workspace_id: None,
        credential_store: CodexCredentialStore::File,
        trusted_runners_only: false,
        wif: None,
        automation: AutomationPolicy::default(),
    };
    let mut form = Form::profile_edit(id.clone(), profile.clone());

    assert_eq!(form.fields.len(), 1);
    assert_eq!(form.fields[0].id, FieldId::Account);
    assert!(form.text_optional(FieldId::Workspace).is_none());
    assert!(form.choice_optional(FieldId::CredentialStore).is_none());

    let submission = form
        .submission()
        .unwrap_or_else(|| panic!("WIF edit form should submit"));
    let Submission::ProfileEdit {
        id: submitted_id,
        expected,
        organization_or_workspace,
        credential_store,
        ..
    } = submission
    else {
        panic!("expected a profile edit submission");
    };
    assert_eq!(submitted_id, id);
    assert_eq!(expected, profile);
    assert_eq!(organization_or_workspace, OptionalEdit::Keep);
    assert_eq!(credential_store, None);
}

#[test]
fn form_navigation_wraps_and_q_is_text() {
    let mut form = Form::profile_add();
    form.focus = 1;
    assert_eq!(
        form.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)),
        FormEvent::Changed
    );
    assert_eq!(
        form.text(FieldId::Name)
            .unwrap_or_else(|error| panic!("name: {error}")),
        "q"
    );
    form.focus = 0;
    let _ = form.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
    assert_eq!(form.focus, form.fields.len() - 1);
    assert_eq!(
        form.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
        FormEvent::Cancel
    );
}
