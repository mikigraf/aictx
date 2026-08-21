use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::model::{Profile, ProfileId};

use super::{FieldId, Form, FormEvent};

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
        billing_domain: crate::model::BillingDomain::AnthropicApi,
        auth: crate::model::ClaudeAuth::ApiKey,
        state_dir: PathBuf::from("/private/state"),
        secret_ref: Some("keyring://private/secret".to_owned()),
        account_hint: Some("person@example.test".to_owned()),
        expected_organization: Some("private-org".to_owned()),
        wif: None,
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
