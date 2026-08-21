use std::collections::BTreeMap;

use ratatui::{Terminal, backend::TestBackend};
use tempfile::TempDir;

use crate::{
    config::AppPaths,
    management,
    model::{
        AuthArg, BillingDomain, Binding, ClaudeAuth, CodexAuth, CodexCredentialStore, Context,
        Profile, Provider, SCHEMA_VERSION, WifConfig,
    },
};

use super::*;

fn test_app() -> App {
    let work = Name::parse("work").unwrap_or_else(|error| panic!("valid name: {error}"));
    let personal = Name::parse("personal").unwrap_or_else(|error| panic!("valid name: {error}"));
    let profile_id: ProfileId = "claude:work"
        .parse()
        .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
    let mut config = Config::default();
    config.profiles.insert(
        profile_id.clone(),
        Profile::Claude {
            billing_domain: BillingDomain::AnthropicApi,
            auth: ClaudeAuth::ApiKey,
            state_dir: PathBuf::from("/tmp/ctxlane-test-state"),
            secret_ref: Some("keyring://TopSecret/credential".to_owned()),
            account_hint: Some("secret-account@example.test".to_owned()),
            expected_organization: Some("secret-org".to_owned()),
            wif: None,
        },
    );
    config.contexts = BTreeMap::from([
        (
            personal.clone(),
            Context {
                claude: Some(profile_id.clone()),
                codex: None,
            },
        ),
        (
            work.clone(),
            Context {
                claude: Some(profile_id),
                codex: None,
            },
        ),
    ]);
    config.default_context = Some(personal);
    let state = MutableState {
        version: SCHEMA_VERSION,
        current_context: Some(work),
    };
    App::from_metadata(config, state, std::env::temp_dir())
}

fn render_text(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal =
        Terminal::new(backend).unwrap_or_else(|error| panic!("test terminal: {error}"));
    terminal
        .draw(|frame| draw(frame, app))
        .unwrap_or_else(|error| panic!("draw test UI: {error}"));
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect::<String>()
}

fn activation_app() -> (TempDir, MetadataStore, App, Name, Name) {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
    let store = MetadataStore::new(paths.clone());
    store
        .initialize()
        .unwrap_or_else(|error| panic!("initialize store: {error}"));

    let personal = Name::parse("personal").unwrap_or_else(|error| panic!("valid name: {error}"));
    let work = Name::parse("work").unwrap_or_else(|error| panic!("valid name: {error}"));
    let personal_id: ProfileId = "claude:personal"
        .parse()
        .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
    let work_id: ProfileId = "claude:work"
        .parse()
        .unwrap_or_else(|error| panic!("valid profile ID: {error}"));

    store
        .update_config(|config| {
            config.profiles.insert(
                personal_id.clone(),
                Profile::Claude {
                    billing_domain: BillingDomain::ClaudeSubscription,
                    auth: ClaudeAuth::SubscriptionToken,
                    state_dir: paths.profile_state_dir(personal_id.provider(), personal_id.name()),
                    secret_ref: Some("keyring://ctxlane/claude-personal".to_owned()),
                    account_hint: None,
                    expected_organization: None,
                    wif: None,
                },
            );
            config.profiles.insert(
                work_id.clone(),
                Profile::Claude {
                    billing_domain: BillingDomain::AnthropicApi,
                    auth: ClaudeAuth::ApiKey,
                    state_dir: paths.profile_state_dir(work_id.provider(), work_id.name()),
                    secret_ref: Some("keyring://ctxlane/claude-work".to_owned()),
                    account_hint: None,
                    expected_organization: None,
                    wif: None,
                },
            );
            config.contexts.insert(
                personal.clone(),
                Context {
                    claude: Some(personal_id),
                    codex: None,
                },
            );
            config.contexts.insert(
                work.clone(),
                Context {
                    claude: Some(work_id),
                    codex: None,
                },
            );
            config.default_context = Some(personal.clone());
            Ok(())
        })
        .unwrap_or_else(|error| panic!("populate store: {error}"));

    let (config, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load metadata: {error}"));
    let app = App::from_metadata(config, state, temporary.path().to_path_buf());
    (temporary, store, app, personal, work)
}

fn press(app: &mut App, store: &MetadataStore, code: KeyCode) {
    handle_key(app, store, KeyEvent::new(code, KeyModifiers::NONE));
}

fn type_text(app: &mut App, store: &MetadataStore, value: &str) {
    for character in value.chars() {
        press(app, store, KeyCode::Char(character));
    }
}

fn add_binding_fixture(
    temporary: &TempDir,
    store: &MetadataStore,
    app: &mut App,
    context: &Name,
) -> PathBuf {
    let path = temporary.path().join("bound-project");
    std::fs::create_dir(&path).unwrap_or_else(|error| panic!("create binding path: {error}"));
    management::add_binding(store, &path, context.clone())
        .unwrap_or_else(|error| panic!("add binding fixture: {error}"));
    app.reload(store)
        .unwrap_or_else(|error| panic!("reload binding fixture: {error}"));
    path.canonicalize()
        .unwrap_or_else(|error| panic!("canonical binding path: {error}"))
}

#[test]
fn tiny_terminal_renders_without_panicking() {
    let text = render_text(&test_app(), 8, 3);
    assert!(!text.is_empty());
}

#[test]
fn profile_view_never_renders_secret_metadata() {
    let mut app = test_app();
    app.panel = Panel::Profiles;
    let text = render_text(&app, 110, 30);
    assert!(text.contains("Profile claude:work"));
    assert!(!text.contains("TopSecret"));
    assert!(!text.contains("secret-account"));
    assert!(!text.contains("secret-org"));
}

#[test]
fn navigation_is_bounded() {
    let mut app = test_app();
    assert_eq!(
        app.selected_context().map(Name::as_str),
        Some("work"),
        "the resolved context should be selected on launch"
    );
    app.move_selection(10);
    assert_eq!(app.context_index, 1);
    app.move_selection(-10);
    assert_eq!(app.context_index, 0);
    app.panel = Panel::Bindings;
    app.move_selection(1);
    assert_eq!(app.binding_index, 0);
}

#[test]
fn header_distinguishes_active_context_from_directory_binding() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut app = test_app();
    let personal = Name::parse("personal").unwrap_or_else(|error| panic!("valid name: {error}"));
    app.cwd = temporary.path().to_path_buf();
    app.config.bindings.push(Binding {
        path: temporary
            .path()
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical path: {error}")),
        context: personal,
    });
    app.resolution =
        resolve_context(&app.config, &app.state, &app.cwd, None).map_err(|error| error.to_string());
    let text = render_text(&app, 120, 30);
    assert!(text.contains("Global: work"));
    assert!(text.contains("Here: personal (directory binding)"));
}

#[test]
fn key_handling_covers_panels_help_and_clean_exit() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = MetadataStore::new(AppPaths::for_root(temporary.path().join("ctxlane")));
    let mut app = test_app();

    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
    );
    assert_eq!(app.panel, Panel::Profiles);
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE),
    );
    assert_eq!(app.panel, Panel::Contexts);
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
    );
    assert!(matches!(app.overlay, Some(Overlay::Help)));
    assert!(render_text(&app, 100, 28).contains("Keyboard shortcuts"));
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
    );
    assert!(app.overlay.is_none());
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
    );
    assert!(app.should_quit);
    assert_eq!(app.exit_code, 0);
}

#[test]
fn account_profile_modal_cancel_and_confirm_use_the_shared_activation_service() {
    let (_temporary, store, mut app, personal, work) = activation_app();
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
    );
    assert_eq!(app.selected_context(), Some(&work));
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
    );
    assert!(matches!(app.overlay, Some(Overlay::Activation(_))));
    let rendered = render_text(&app, 100, 28);
    assert!(rendered.contains("Account profile change"));
    assert!(rendered.contains("claude:personal"));
    assert!(rendered.contains("claude:work"));

    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
    );
    assert!(app.overlay.is_none());
    let (config, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load cancelled state: {error}"));
    assert_eq!(state.current_context, None);
    assert_eq!(config.default_context.as_ref(), Some(&personal));

    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
    );
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
    );
    let (config, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load activated state: {error}"));
    assert_eq!(state.current_context.as_ref(), Some(&work));
    assert_eq!(config.default_context.as_ref(), Some(&personal));
    assert!(app.overlay.is_none());
    assert!(
        app.message
            .as_ref()
            .is_some_and(|message| message.text.contains("Global active context: work"))
    );
}

#[test]
fn stale_account_profile_modal_requires_reviewing_the_updated_change() {
    let (_temporary, store, mut app, _personal, work) = activation_app();
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
    );
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
    );
    assert!(matches!(app.overlay, Some(Overlay::Activation(_))));

    let codex_id: ProfileId = "codex:work"
        .parse()
        .unwrap_or_else(|error| panic!("valid profile ID: {error}"));
    let codex_state = store
        .paths()
        .profile_state_dir(codex_id.provider(), codex_id.name());
    store
        .update_config(|config| {
            config.profiles.insert(
                codex_id.clone(),
                Profile::Codex {
                    billing_domain: BillingDomain::OpenaiApi,
                    auth: CodexAuth::ApiKey,
                    state_dir: codex_state,
                    secret_ref: Some("keyring://ctxlane/codex-work".to_owned()),
                    account_hint: None,
                    expected_workspace_id: None,
                    credential_store: CodexCredentialStore::File,
                    trusted_runners_only: false,
                },
            );
            config
                .contexts
                .get_mut(&work)
                .ok_or_else(|| Error::ContextNotFound(work.to_string()))?
                .codex = Some(codex_id);
            Ok(())
        })
        .unwrap_or_else(|error| panic!("change profile fingerprint: {error}"));

    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
    );
    assert!(matches!(app.overlay, Some(Overlay::Activation(_))));
    assert!(app.message.as_ref().is_some_and(|message| {
        message.text.contains("Context or profile state changed")
            && message.level == MessageLevel::Warning
    }));
    let (_, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load unchanged state: {error}"));
    assert_eq!(state.current_context, None);
}

#[test]
fn control_c_requests_exit_130_without_other_state_changes() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = MetadataStore::new(AppPaths::for_root(temporary.path().join("ctxlane")));
    let mut app = test_app();
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(app.should_quit);
    assert_eq!(app.exit_code, 130);
}

#[test]
fn crud_shortcuts_open_every_panel_operation_and_escape_does_not_persist() {
    let (temporary, store, mut app, personal, _work) = activation_app();
    let _binding_path = add_binding_fixture(&temporary, &store, &mut app, &personal);
    let before = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load metadata before cancellations: {error}"));

    app.panel = Panel::Contexts;
    press(&mut app, &store, KeyCode::Char('a'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::ContextAdd,
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::Char('e'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::ContextEdit { .. },
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::Char('R'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::ContextRename { .. },
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::Char('d'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Removal(Removal::Context { .. }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    assert!(app.overlay.is_none());

    app.panel = Panel::Profiles;
    press(&mut app, &store, KeyCode::Char('a'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::ProfileAdd,
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::Char('e'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::ProfileEdit { .. },
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::F(2));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::ProfileRename { .. },
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::Char('d'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Removal(Removal::Profile { .. }))
    ));
    press(&mut app, &store, KeyCode::Esc);

    app.panel = Panel::Bindings;
    press(&mut app, &store, KeyCode::Char('a'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::BindingAdd,
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::Char('e'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::BindingEdit { .. },
            focus: 1,
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::Char('R'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Form(Form {
            operation: editor::FormOperation::BindingEdit { .. },
            focus: 0,
            ..
        }))
    ));
    press(&mut app, &store, KeyCode::Esc);
    press(&mut app, &store, KeyCode::Char('d'));
    assert!(matches!(
        app.overlay,
        Some(Overlay::Removal(Removal::Binding { .. }))
    ));
    press(&mut app, &store, KeyCode::Esc);

    let after = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load metadata after cancellations: {error}"));
    assert_eq!(after, before);
}

#[test]
fn context_edit_requires_visible_selection_review() {
    let (_temporary, store, mut app, personal, _work) = activation_app();
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE),
    );
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
    );
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
    );
    assert!(matches!(app.overlay, Some(Overlay::SelectionChange(_))));
    assert!(render_text(&app, 100, 30).contains("Review account selection change"));
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
    );
    let config = store
        .load_config()
        .unwrap_or_else(|error| panic!("load config: {error}"));
    assert_eq!(
        config.contexts[&personal]
            .claude
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("claude:personal")
    );
}

#[test]
fn invalid_form_stays_open_and_does_not_persist() {
    let (_temporary, store, mut app, _personal, _work) = activation_app();
    let before = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load metadata before invalid form: {error}"));
    press(&mut app, &store, KeyCode::Char('a'));
    press(&mut app, &store, KeyCode::Enter);
    let Some(Overlay::Form(form)) = app.overlay.as_ref() else {
        panic!("invalid context form should remain open");
    };
    assert!(form.error.is_some());
    assert!(render_text(&app, 100, 30).contains("invalid"));
    let after = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load metadata after invalid form: {error}"));
    assert_eq!(after, before);
}

#[test]
fn removal_requires_y_and_n_cancels_without_persistence() {
    let (temporary, store, mut app, personal, _work) = activation_app();
    let binding_path = add_binding_fixture(&temporary, &store, &mut app, &personal);
    app.panel = Panel::Bindings;

    press(&mut app, &store, KeyCode::Char('d'));
    press(&mut app, &store, KeyCode::Char('N'));
    assert!(app.overlay.is_none());
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config after cancelled removal: {error}"))
            .bindings
            .iter()
            .any(|binding| binding.path == binding_path)
    );

    press(&mut app, &store, KeyCode::Char('d'));
    press(&mut app, &store, KeyCode::Char('y'));
    assert!(app.overlay.is_none());
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config after confirmed removal: {error}"))
            .bindings
            .is_empty()
    );
}

#[test]
fn hidden_modal_cannot_save_or_confirm() {
    let (_temporary, store, mut app, _personal, work) = activation_app();
    app.context_index = 1;
    open_removal(&mut app);
    assert!(matches!(app.overlay, Some(Overlay::Removal(_))));
    app.viewport_width = 60;
    app.viewport_height = 10;
    press(&mut app, &store, KeyCode::Char('y'));
    assert!(matches!(app.overlay, Some(Overlay::Removal(_))));
    assert!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"))
            .contexts
            .contains_key(&work)
    );
    let text = render_text(&app, 60, 10);
    assert!(text.contains("Writes"));

    press(&mut app, &store, KeyCode::Esc);
    app.viewport_width = u16::MAX;
    app.viewport_height = u16::MAX;
    app.panel = Panel::Profiles;
    press(&mut app, &store, KeyCode::Char('e'));
    press(&mut app, &store, KeyCode::Char('x'));
    app.viewport_width = 60;
    app.viewport_height = 10;
    press(&mut app, &store, KeyCode::Enter);
    assert!(matches!(app.overlay, Some(Overlay::Form(_))));
    let selected = app
        .selected_profile()
        .unwrap_or_else(|| panic!("selected profile"));
    assert_eq!(
        store
            .load_config()
            .unwrap_or_else(|error| panic!("load config after hidden save: {error}"))
            .profiles[selected]
            .account_hint(),
        None
    );
}

#[test]
fn control_c_exits_130_from_form_and_removal_without_persisting() {
    let (_temporary, store, mut app, _personal, _work) = activation_app();
    let before = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load metadata before Ctrl-C: {error}"));

    app.panel = Panel::Profiles;
    press(&mut app, &store, KeyCode::Char('e'));
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(app.should_quit);
    assert_eq!(app.exit_code, 130);
    assert!(matches!(app.overlay, Some(Overlay::Form(_))));

    app.should_quit = false;
    app.exit_code = 0;
    app.overlay = None;
    app.panel = Panel::Contexts;
    press(&mut app, &store, KeyCode::Char('d'));
    handle_key(
        &mut app,
        &store,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(app.should_quit);
    assert_eq!(app.exit_code, 130);
    assert!(matches!(app.overlay, Some(Overlay::Removal(_))));

    let after = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load metadata after Ctrl-C: {error}"));
    assert_eq!(after, before);
}

#[test]
fn valid_forms_add_and_select_a_context_profile_and_binding() {
    let (temporary, store, mut app, _personal, _work) = activation_app();

    app.panel = Panel::Contexts;
    press(&mut app, &store, KeyCode::Char('a'));
    type_text(&mut app, &store, "new-context");
    press(&mut app, &store, KeyCode::Tab);
    press(&mut app, &store, KeyCode::Right);
    press(&mut app, &store, KeyCode::Enter);
    let context_name =
        Name::parse("new-context").unwrap_or_else(|error| panic!("context name: {error}"));
    assert!(app.overlay.is_none());
    assert_eq!(app.selected_context(), Some(&context_name));

    app.panel = Panel::Profiles;
    press(&mut app, &store, KeyCode::Char('a'));
    press(&mut app, &store, KeyCode::Right);
    press(&mut app, &store, KeyCode::Tab);
    type_text(&mut app, &store, "new-profile");
    press(&mut app, &store, KeyCode::Tab);
    press(&mut app, &store, KeyCode::Right);
    press(&mut app, &store, KeyCode::Enter);
    let profile_id: ProfileId = "codex:new-profile"
        .parse()
        .unwrap_or_else(|error| panic!("profile ID: {error}"));
    assert!(app.overlay.is_none());
    assert_eq!(app.selected_profile(), Some(&profile_id));

    let binding_path = temporary.path().join("new-bound-project");
    std::fs::create_dir(&binding_path)
        .unwrap_or_else(|error| panic!("create new binding path: {error}"));
    app.cwd.clone_from(&binding_path);
    app.panel = Panel::Bindings;
    press(&mut app, &store, KeyCode::Char('a'));
    press(&mut app, &store, KeyCode::Enter);
    let canonical_binding = binding_path
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonical new binding: {error}"));
    assert!(app.overlay.is_none());
    assert_eq!(
        app.config
            .bindings
            .get(app.binding_index)
            .map(|binding| &binding.path),
        Some(&canonical_binding)
    );
}

#[test]
fn context_profile_and_binding_mutations_round_trip_without_credentials() {
    let (temporary, store, mut app, _personal, _work) = activation_app();
    let personal_id: ProfileId = "claude:personal"
        .parse()
        .unwrap_or_else(|error| panic!("profile: {error}"));
    let scratch = Name::parse("scratch").unwrap_or_else(|error| panic!("name: {error}"));
    apply_submission(
        &mut app,
        &store,
        Submission::ContextAdd {
            name: scratch.clone(),
            context: Context {
                claude: Some(personal_id),
                codex: None,
            },
        },
    )
    .unwrap_or_else(|error| panic!("add context: {error}"));
    assert_eq!(app.selected_context(), Some(&scratch));
    let renamed = Name::parse("scratch2").unwrap_or_else(|error| panic!("name: {error}"));
    let expected_context = app.config.contexts[&scratch].clone();
    apply_submission(
        &mut app,
        &store,
        Submission::ContextRename {
            name: scratch,
            expected: expected_context,
            replacement: renamed.clone(),
        },
    )
    .unwrap_or_else(|error| panic!("rename context: {error}"));
    assert_eq!(app.selected_context(), Some(&renamed));

    let draft = editor::ProfileDraft {
        provider: Provider::Codex,
        name: Name::parse("scratch").unwrap_or_else(|error| panic!("name: {error}")),
        auth: AuthArg::ApiKey,
        account: None,
        organization: None,
        workspace: None,
        organization_id: None,
        federation_rule_id: None,
        service_account_id: None,
        identity_token_file: None,
        credential_store: CodexCredentialStore::File,
    };
    apply_submission(&mut app, &store, Submission::ProfileAdd(draft))
        .unwrap_or_else(|error| panic!("add profile: {error}"));
    let id: ProfileId = "codex:scratch"
        .parse()
        .unwrap_or_else(|error| panic!("profile: {error}"));
    assert_eq!(app.selected_profile(), Some(&id));
    let expected_profile = app.config.profiles[&id].clone();
    apply_submission(
        &mut app,
        &store,
        Submission::ProfileEdit {
            id: id.clone(),
            expected: expected_profile,
            account: editor::OptionalEdit::Set("typed-by-user".to_owned()),
            organization_or_workspace: editor::OptionalEdit::Keep,
            credential_store: Some(CodexCredentialStore::Auto),
        },
    )
    .unwrap_or_else(|error| panic!("edit profile: {error}"));
    let expected_profile = app.config.profiles[&id].clone();
    let new_name = Name::parse("renamed").unwrap_or_else(|error| panic!("name: {error}"));
    apply_submission(
        &mut app,
        &store,
        Submission::ProfileRename {
            id,
            expected: expected_profile,
            replacement: new_name,
        },
    )
    .unwrap_or_else(|error| panic!("rename profile: {error}"));
    let renamed_id: ProfileId = "codex:renamed"
        .parse()
        .unwrap_or_else(|error| panic!("profile: {error}"));
    assert_eq!(app.selected_profile(), Some(&renamed_id));

    let binding_dir = temporary.path().join("bound project");
    std::fs::create_dir(&binding_dir).unwrap_or_else(|error| panic!("create binding: {error}"));
    apply_submission(
        &mut app,
        &store,
        Submission::BindingAdd {
            path: binding_dir.clone(),
            context: renamed.clone(),
        },
    )
    .unwrap_or_else(|error| panic!("add binding: {error}"));
    assert_eq!(
        app.config
            .bindings
            .get(app.binding_index)
            .map(|binding| &binding.path),
        Some(
            &binding_dir
                .canonicalize()
                .unwrap_or_else(|error| panic!("canonical binding after add: {error}"))
        )
    );
    let expected_binding = app.config.bindings[0].clone();
    apply_removal(
        &mut app,
        &store,
        &Removal::Binding {
            expected: expected_binding,
        },
    )
    .unwrap_or_else(|error| panic!("remove binding: {error}"));
    let expected_context = app.config.contexts[&renamed].clone();
    apply_removal(
        &mut app,
        &store,
        &Removal::Context {
            name: renamed.clone(),
            expected: expected_context,
        },
    )
    .unwrap_or_else(|error| panic!("remove context: {error}"));
    let expected_profile = app.config.profiles[&renamed_id].clone();
    apply_removal(
        &mut app,
        &store,
        &Removal::Profile {
            id: renamed_id.clone(),
            expected: expected_profile,
        },
    )
    .unwrap_or_else(|error| panic!("remove profile: {error}"));
    assert!(!app.config.profiles.contains_key(&renamed_id));
    assert!(app.config.bindings.is_empty());
}

#[test]
fn wif_profile_add_preserves_new_pin_and_route_without_a_secret() {
    let (temporary, store, mut app, _personal, _work) = activation_app();
    let token_file = temporary.path().join("identity.jwt");
    let draft = editor::ProfileDraft {
        provider: Provider::Claude,
        name: Name::parse("ci").unwrap_or_else(|error| panic!("WIF profile name: {error}")),
        auth: AuthArg::Wif,
        account: Some("new-account-label".to_owned()),
        organization: Some("new-expected-organization".to_owned()),
        workspace: Some("new-wif-workspace".to_owned()),
        organization_id: Some("new-wif-organization-id".to_owned()),
        federation_rule_id: Some("new-wif-federation-rule".to_owned()),
        service_account_id: Some("new-wif-service-account".to_owned()),
        identity_token_file: Some(token_file.clone()),
        credential_store: CodexCredentialStore::File,
    };
    apply_submission(&mut app, &store, Submission::ProfileAdd(draft))
        .unwrap_or_else(|error| panic!("add WIF profile: {error}"));

    let id: ProfileId = "claude:ci"
        .parse()
        .unwrap_or_else(|error| panic!("WIF profile ID: {error}"));
    let Profile::Claude {
        secret_ref,
        account_hint,
        expected_organization,
        wif: Some(wif),
        ..
    } = &app.config.profiles[&id]
    else {
        panic!("stored Claude WIF profile");
    };
    assert_eq!(secret_ref, &None);
    assert_eq!(account_hint.as_deref(), Some("new-account-label"));
    assert_eq!(
        expected_organization.as_deref(),
        Some("new-expected-organization")
    );
    assert_eq!(wif.organization_id, "new-wif-organization-id");
    assert_eq!(wif.federation_rule_id, "new-wif-federation-rule");
    assert_eq!(wif.service_account_id, "new-wif-service-account");
    assert_eq!(wif.workspace_id.as_deref(), Some("new-wif-workspace"));
    assert_eq!(wif.identity_token_file, token_file);
}

#[test]
fn profile_mutation_views_never_reveal_persisted_identity_values() {
    let mut app = test_app();
    let wif_id: ProfileId = "claude:wif"
        .parse()
        .unwrap_or_else(|error| panic!("WIF profile ID: {error}"));
    app.config.profiles.insert(
        wif_id,
        Profile::Claude {
            billing_domain: BillingDomain::AnthropicApi,
            auth: ClaudeAuth::Wif,
            state_dir: PathBuf::from("/private/wif-state-canary"),
            secret_ref: None,
            account_hint: Some("wif-account-canary".to_owned()),
            expected_organization: Some("wif-expected-org-canary".to_owned()),
            wif: Some(WifConfig {
                organization_id: "wif-organization-id-canary".to_owned(),
                federation_rule_id: "wif-federation-rule-canary".to_owned(),
                service_account_id: "wif-service-account-canary".to_owned(),
                workspace_id: Some("wif-workspace-canary".to_owned()),
                identity_token_file: PathBuf::from("/private/wif-token-file-canary"),
            }),
        },
    );
    let codex_id: ProfileId = "codex:work"
        .parse()
        .unwrap_or_else(|error| panic!("Codex profile ID: {error}"));
    app.config.profiles.insert(
        codex_id,
        Profile::Codex {
            billing_domain: BillingDomain::OpenaiApi,
            auth: CodexAuth::AccessToken,
            state_dir: PathBuf::from("/private/codex-state-canary"),
            secret_ref: Some("keyring://codex-secret-ref-canary/credential".to_owned()),
            account_hint: Some("codex-account-canary".to_owned()),
            expected_workspace_id: Some("codex-workspace-canary".to_owned()),
            credential_store: CodexCredentialStore::Keyring,
            trusted_runners_only: true,
        },
    );

    let canaries = [
        "TopSecret",
        "secret-account",
        "secret-org",
        "ctxlane-test-state",
        "wif-state-canary",
        "wif-account-canary",
        "wif-expected-org-canary",
        "wif-organization-id-canary",
        "wif-federation-rule-canary",
        "wif-service-account-canary",
        "wif-workspace-canary",
        "wif-token-file-canary",
        "codex-state-canary",
        "codex-secret-ref-canary",
        "codex-account-canary",
        "codex-workspace-canary",
    ];
    app.panel = Panel::Profiles;
    let profiles = app
        .config
        .profiles
        .iter()
        .map(|(id, profile)| (id.clone(), profile.clone()))
        .collect::<Vec<_>>();
    for (id, profile) in profiles {
        app.profile_index = app
            .config
            .profiles
            .keys()
            .position(|candidate| candidate == &id)
            .unwrap_or_else(|| panic!("profile index for {id}"));
        let renders = [
            {
                app.overlay = None;
                render_text(&app, 120, 40)
            },
            {
                app.overlay = Some(Overlay::Form(Form::profile_edit(
                    id.clone(),
                    profile.clone(),
                )));
                render_text(&app, 120, 40)
            },
            {
                app.overlay = Some(Overlay::Form(Form::profile_rename(
                    id.clone(),
                    profile.clone(),
                )));
                render_text(&app, 120, 40)
            },
            {
                app.overlay = Some(Overlay::Removal(Removal::Profile {
                    id: id.clone(),
                    expected: profile.clone(),
                }));
                render_text(&app, 120, 40)
            },
        ];
        for rendered in renders {
            for canary in canaries {
                assert!(
                    !rendered.contains(canary),
                    "profile {id} render exposed persisted identity canary {canary}"
                );
            }
        }
    }
}
