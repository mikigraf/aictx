use std::{fmt, path::Path};

use crate::{
    Error, Result,
    config::MetadataStore,
    model::{BillingDomain, Config, Context, Name, Profile, ProfileId, Provider},
    resolver::{ResolutionSource, context_not_found, resolve_context_at_canonical_directory},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionConfirmation {
    None,
    Change(SelectionChange),
    AnyChange,
}

/// A safe summary of one provider profile selected by a context.
///
/// This type deliberately excludes secret references, account hints, workspace IDs,
/// organization IDs, and local state paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSelection {
    id: ProfileId,
    auth: String,
    billing_domain: BillingDomain,
}

impl ProfileSelection {
    #[must_use]
    pub const fn id(&self) -> &ProfileId {
        &self.id
    }

    #[must_use]
    pub fn auth_label(&self) -> &str {
        &self.auth
    }

    #[must_use]
    pub const fn billing_domain(&self) -> BillingDomain {
        self.billing_domain
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ProfileFingerprint {
    id: ProfileId,
    profile: Profile,
}

/// An exact identity-selection change that must be confirmed.
///
/// Equality includes the full selected profile configuration so a confirmation
/// becomes stale if routing-sensitive metadata changes before activation. Debug
/// output and public accessors expose only safe profile summaries.
#[derive(Clone)]
pub struct SelectionChange {
    previous: Name,
    target: Name,
    details: Box<SelectionDetails>,
}

#[derive(Clone, Eq, PartialEq)]
struct SelectionDetails {
    previous_profiles: [Option<ProfileSelection>; 2],
    target_profiles: [Option<ProfileSelection>; 2],
    previous_fingerprints: [Option<ProfileFingerprint>; 2],
    target_fingerprints: [Option<ProfileFingerprint>; 2],
}

impl SelectionChange {
    #[must_use]
    pub const fn previous(&self) -> &Name {
        &self.previous
    }

    #[must_use]
    pub const fn target(&self) -> &Name {
        &self.target
    }

    #[must_use]
    pub const fn previous_profiles(&self) -> &[Option<ProfileSelection>; 2] {
        &self.details.previous_profiles
    }

    #[must_use]
    pub const fn target_profiles(&self) -> &[Option<ProfileSelection>; 2] {
        &self.details.target_profiles
    }
}

impl fmt::Debug for SelectionChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectionChange")
            .field("previous", &self.previous)
            .field("target", &self.target)
            .field("previous_profiles", &self.details.previous_profiles)
            .field("target_profiles", &self.details.target_profiles)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SelectionChange {
    fn eq(&self, other: &Self) -> bool {
        self.previous == other.previous
            && self.target == other.target
            && self.details.previous_fingerprints == other.details.previous_fingerprints
            && self.details.target_fingerprints == other.details.target_fingerprints
    }
}

impl Eq for SelectionChange {}

/// The selection written by activation and the context effective in its directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationReceipt {
    global_context: Name,
    effective_context: Name,
    source: ResolutionSource,
    global_profiles: [Option<ProfileSelection>; 2],
    effective_profiles: [Option<ProfileSelection>; 2],
}

impl ActivationReceipt {
    #[must_use]
    pub const fn global_context(&self) -> &Name {
        &self.global_context
    }

    #[must_use]
    pub const fn effective_context(&self) -> &Name {
        &self.effective_context
    }

    #[must_use]
    pub const fn source(&self) -> ResolutionSource {
        self.source
    }

    #[must_use]
    pub const fn global_profiles(&self) -> &[Option<ProfileSelection>; 2] {
        &self.global_profiles
    }

    #[must_use]
    pub const fn effective_profiles(&self) -> &[Option<ProfileSelection>; 2] {
        &self.effective_profiles
    }

    #[must_use]
    pub fn is_shadowed(&self) -> bool {
        self.global_context != self.effective_context
    }
}

/// Backward-compatible name retained for callers of the v0.1 activation API.
pub type BillingConfirmation = SelectionConfirmation;

/// Backward-compatible name retained for callers of the v0.1 activation API.
pub type BillingChange = SelectionChange;

/// Return a fingerprint of the profile-selection change that must be confirmed, if any.
pub fn required_selection_change(
    store: &MetadataStore,
    target: &Name,
) -> Result<Option<SelectionChange>> {
    let (config, state) = store.load_metadata()?;
    if !config.contexts.contains_key(target) {
        return Err(context_not_found(&config, target));
    }
    let previous = state
        .current_context
        .as_ref()
        .or(config.default_context.as_ref());
    Ok(previous.and_then(|previous| {
        selection_change(&config, previous, target)
            // The serialized v1 setting name is retained for compatibility. It now
            // protects every exact provider-profile selection change.
            .filter(|_| config.settings.require_billing_confirmation_on_change)
    }))
}

/// Backward-compatible wrapper for the v0.1 function name.
pub fn required_billing_change(
    store: &MetadataStore,
    target: &Name,
) -> Result<Option<BillingChange>> {
    required_selection_change(store, target)
}

/// Select a context while rechecking the identity-selection policy under the metadata lock.
pub fn activate(
    store: &MetadataStore,
    target: &Name,
    confirmation: &SelectionConfirmation,
) -> Result<()> {
    activate_inner(store, target, confirmation, None).map(drop)
}

/// Select a context and atomically describe what the supplied directory will resolve to.
pub fn activate_with_receipt(
    store: &MetadataStore,
    target: &Name,
    confirmation: &SelectionConfirmation,
    cwd: &Path,
) -> Result<ActivationReceipt> {
    let canonical_cwd = cwd.canonicalize().map_err(|source| Error::ReadFile {
        path: cwd.to_path_buf(),
        source,
    })?;
    activate_inner(store, target, confirmation, Some(&canonical_cwd))?.ok_or_else(|| {
        Error::InvalidInput("activation receipt requires a current directory".to_owned())
    })
}

fn activate_inner(
    store: &MetadataStore,
    target: &Name,
    confirmation: &SelectionConfirmation,
    canonical_cwd: Option<&Path>,
) -> Result<Option<ActivationReceipt>> {
    store.update_metadata(|config, state| {
        if !config.contexts.contains_key(target) {
            return Err(context_not_found(config, target));
        }
        let previous = state
            .current_context
            .as_ref()
            .or(config.default_context.as_ref());
        let current_change = previous.and_then(|previous| selection_change(config, previous, target));
        if let Some(current_change) = current_change
            && config.settings.require_billing_confirmation_on_change
        {
            let confirmed = match confirmation {
                SelectionConfirmation::AnyChange => true,
                SelectionConfirmation::Change(expected) => expected == &current_change,
                SelectionConfirmation::None => false,
            };
            if !confirmed {
                return Err(Error::InteractionRequired(
                    "account profile change requires confirmation; the active context or profile configuration may have changed"
                        .to_owned(),
                ));
            }
        }
        state.current_context = Some(target.clone());
        canonical_cwd.map(|canonical_cwd| {
            let resolved = resolve_context_at_canonical_directory(config, state, canonical_cwd)?;
            let global_profiles = profile_selections_for_context(config, target);
            let effective_profiles = profile_selections_for_context(config, &resolved.name);
            Ok(ActivationReceipt {
                global_context: target.clone(),
                effective_context: resolved.name,
                source: resolved.source,
                global_profiles,
                effective_profiles,
            })
        })
        .transpose()
    })
}

fn selection_change(config: &Config, previous: &Name, target: &Name) -> Option<SelectionChange> {
    if previous == target {
        return None;
    }
    let previous_fingerprints = profile_fingerprints(config, previous);
    let target_fingerprints = profile_fingerprints(config, target);
    (previous_fingerprints != target_fingerprints).then(|| SelectionChange {
        previous: previous.clone(),
        target: target.clone(),
        details: Box::new(SelectionDetails {
            previous_profiles: profile_selections(&previous_fingerprints),
            target_profiles: profile_selections(&target_fingerprints),
            previous_fingerprints,
            target_fingerprints,
        }),
    })
}

fn profile_fingerprints(config: &Config, context: &Name) -> [Option<ProfileFingerprint>; 2] {
    let context = config.contexts.get(context);
    [Provider::Claude, Provider::Codex].map(|provider| {
        context
            .and_then(|context: &Context| context.profile(provider))
            .and_then(|id| {
                config.profiles.get(id).map(|profile| ProfileFingerprint {
                    id: id.clone(),
                    profile: profile.clone(),
                })
            })
    })
}

fn profile_selections(
    fingerprints: &[Option<ProfileFingerprint>; 2],
) -> [Option<ProfileSelection>; 2] {
    fingerprints.each_ref().map(|fingerprint| {
        fingerprint.as_ref().map(|fingerprint| ProfileSelection {
            id: fingerprint.id.clone(),
            auth: fingerprint.profile.auth_label(),
            billing_domain: fingerprint.profile.billing_domain(),
        })
    })
}

fn profile_selections_for_context(
    config: &Config,
    context: &Name,
) -> [Option<ProfileSelection>; 2] {
    profile_selections(&profile_fingerprints(config, context))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::{
        config::{AppPaths, MetadataStore},
        model::{
            AutomationPolicy, BillingDomain, ClaudeAuth, CodexAuth, CodexCredentialStore, Context,
            Name, Profile, ProfileId, ProfileUid,
        },
    };

    use super::*;

    fn fixture() -> (TempDir, MetadataStore, Name, Name) {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::for_root(temporary.path().join("ctxlane"));
        let store = MetadataStore::new(paths.clone());
        store
            .initialize()
            .unwrap_or_else(|error| panic!("initialize store: {error}"));

        let personal =
            Name::parse("personal").unwrap_or_else(|error| panic!("valid name: {error}"));
        let work = Name::parse("work").unwrap_or_else(|error| panic!("valid name: {error}"));
        let personal_id: ProfileId = "claude:personal"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile: {error}"));
        let work_id: ProfileId = "claude:work"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile: {error}"));
        let personal_state = paths.profile_state_dir(personal_id.provider(), personal_id.name());
        let work_state = paths.profile_state_dir(work_id.provider(), work_id.name());

        store
            .update_config(|config| {
                let personal_profile_uid = ProfileUid::for_state_dir(
                    &config.installation_uid,
                    personal_id.provider(),
                    &personal_state,
                )?;
                let work_profile_uid = ProfileUid::for_state_dir(
                    &config.installation_uid,
                    work_id.provider(),
                    &work_state,
                )?;
                config.profiles.insert(
                    personal_id.clone(),
                    Profile::Claude {
                        profile_uid: personal_profile_uid,
                        billing_domain: BillingDomain::ClaudeSubscription,
                        auth: ClaudeAuth::SubscriptionToken,
                        state_dir: personal_state,
                        secret_ref: Some("keyring://ctxlane/claude-personal".to_owned()),
                        account_hint: None,
                        expected_organization: None,
                        wif: None,
                        automation: AutomationPolicy::default(),
                    },
                );
                config.profiles.insert(
                    work_id.clone(),
                    Profile::Claude {
                        profile_uid: work_profile_uid,
                        billing_domain: BillingDomain::AnthropicApi,
                        auth: ClaudeAuth::ApiKey,
                        state_dir: work_state,
                        secret_ref: Some("keyring://ctxlane/claude-work".to_owned()),
                        account_hint: None,
                        expected_organization: None,
                        wif: None,
                        automation: AutomationPolicy::default(),
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

        (temporary, store, personal, work)
    }

    #[test]
    fn profile_selection_change_requires_matching_confirmation() {
        let (_temporary, store, _personal, work) = fixture();
        let change = required_selection_change(&store, &work)
            .unwrap_or_else(|error| panic!("prepare activation: {error}"))
            .unwrap_or_else(|| panic!("profile change should require confirmation"));

        let error = match activate(&store, &work, &SelectionConfirmation::None) {
            Ok(()) => panic!("unconfirmed activation should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InteractionRequired(_)));
        activate(&store, &work, &SelectionConfirmation::Change(change))
            .unwrap_or_else(|error| panic!("confirmed activation: {error}"));

        let config = store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"));
        let state = store
            .load_state(&config)
            .unwrap_or_else(|error| panic!("load state: {error}"));
        assert_eq!(state.current_context.as_ref(), Some(&work));
    }

    #[test]
    fn same_billing_domain_different_profile_requires_confirmation() {
        let (_temporary, store, _personal, work) = fixture();
        store
            .update_config(|config| {
                let profile = config
                    .profiles
                    .get_mut(
                        &"claude:work"
                            .parse::<ProfileId>()
                            .unwrap_or_else(|error| panic!("valid profile ID: {error}")),
                    )
                    .ok_or_else(|| Error::ProfileNotFound("claude:work".to_owned()))?;
                if let Profile::Claude {
                    billing_domain,
                    auth,
                    ..
                } = profile
                {
                    *billing_domain = BillingDomain::ClaudeSubscription;
                    *auth = ClaudeAuth::SubscriptionToken;
                }
                Ok(())
            })
            .unwrap_or_else(|error| panic!("align billing domain: {error}"));

        let change = required_selection_change(&store, &work)
            .unwrap_or_else(|error| panic!("prepare activation: {error}"))
            .unwrap_or_else(|| panic!("profile ID change should require confirmation"));
        assert_eq!(
            change.previous_profiles()[0]
                .as_ref()
                .map(ProfileSelection::billing_domain),
            change.target_profiles()[0]
                .as_ref()
                .map(ProfileSelection::billing_domain)
        );
        assert_ne!(
            change.previous_profiles()[0]
                .as_ref()
                .map(ProfileSelection::id),
            change.target_profiles()[0]
                .as_ref()
                .map(ProfileSelection::id)
        );
        let error = match activate(&store, &work, &SelectionConfirmation::None) {
            Ok(()) => panic!("unconfirmed activation should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InteractionRequired(_)));
    }

    #[test]
    fn provider_add_remove_requires_confirmation_but_context_alias_does_not() {
        let (_temporary, store, personal, _work) = fixture();
        let alias = Name::parse("alias").unwrap_or_else(|error| panic!("valid name: {error}"));
        let expanded =
            Name::parse("expanded").unwrap_or_else(|error| panic!("valid name: {error}"));
        let claude_id: ProfileId = "claude:personal"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile: {error}"));
        let codex_id: ProfileId = "codex:personal"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile: {error}"));
        let codex_state = store
            .paths()
            .profile_state_dir(codex_id.provider(), codex_id.name());
        store
            .update_config(|config| {
                let codex_profile_uid = ProfileUid::for_state_dir(
                    &config.installation_uid,
                    codex_id.provider(),
                    &codex_state,
                )?;
                config.profiles.insert(
                    codex_id.clone(),
                    Profile::Codex {
                        profile_uid: codex_profile_uid,
                        billing_domain: BillingDomain::ChatgptSubscription,
                        auth: CodexAuth::ChatgptOauth,
                        state_dir: codex_state,
                        secret_ref: None,
                        account_hint: None,
                        expected_workspace_id: None,
                        credential_store: CodexCredentialStore::File,
                        trusted_runners_only: false,
                        wif: None,
                        automation: AutomationPolicy::default(),
                    },
                );
                config.contexts.insert(
                    alias.clone(),
                    Context {
                        claude: Some(claude_id.clone()),
                        codex: None,
                    },
                );
                config.contexts.insert(
                    expanded.clone(),
                    Context {
                        claude: Some(claude_id),
                        codex: Some(codex_id),
                    },
                );
                Ok(())
            })
            .unwrap_or_else(|error| panic!("add context variants: {error}"));

        assert!(
            required_selection_change(&store, &alias)
                .unwrap_or_else(|error| panic!("check alias: {error}"))
                .is_none(),
            "two context names with identical profile mappings are the same identity selection"
        );

        let added = required_selection_change(&store, &expanded)
            .unwrap_or_else(|error| panic!("check provider addition: {error}"))
            .unwrap_or_else(|| panic!("provider addition should require confirmation"));
        assert!(added.previous_profiles()[1].is_none());
        assert!(added.target_profiles()[1].is_some());
        activate(&store, &expanded, &SelectionConfirmation::AnyChange)
            .unwrap_or_else(|error| panic!("activate expanded context: {error}"));

        let removed = required_selection_change(&store, &personal)
            .unwrap_or_else(|error| panic!("check provider removal: {error}"))
            .unwrap_or_else(|| panic!("provider removal should require confirmation"));
        assert!(removed.previous_profiles()[1].is_some());
        assert!(removed.target_profiles()[1].is_none());
    }

    #[test]
    fn stale_full_profile_fingerprint_is_rejected_without_exposing_private_fields() {
        let (_temporary, store, _personal, work) = fixture();
        let original_change = required_selection_change(&store, &work)
            .unwrap_or_else(|error| panic!("prepare activation: {error}"))
            .unwrap_or_else(|| panic!("profile change should require confirmation"));
        let debug = format!("{original_change:?}");
        assert!(!debug.contains("keyring://"));

        store
            .update_config(|config| {
                let work_id: ProfileId = "claude:work"
                    .parse()
                    .unwrap_or_else(|error| panic!("valid profile: {error}"));
                let profile = config
                    .profiles
                    .get_mut(&work_id)
                    .ok_or_else(|| Error::ProfileNotFound(work_id.to_string()))?;
                if let Profile::Claude { account_hint, .. } = profile {
                    *account_hint = Some("changed-private-hint".to_owned());
                }
                Ok(())
            })
            .unwrap_or_else(|error| panic!("change target identity metadata: {error}"));

        let fresh = required_selection_change(&store, &work)
            .unwrap_or_else(|error| panic!("refresh activation: {error}"))
            .unwrap_or_else(|| panic!("changed profile should require confirmation"));
        assert_ne!(original_change, fresh);
        let error = match activate(
            &store,
            &work,
            &SelectionConfirmation::Change(original_change),
        ) {
            Ok(()) => panic!("stale confirmation should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InteractionRequired(_)));

        let config = store
            .load_config()
            .unwrap_or_else(|error| panic!("load config: {error}"));
        let state = store
            .load_state(&config)
            .unwrap_or_else(|error| panic!("load state: {error}"));
        assert!(state.current_context.is_none());
    }

    #[test]
    fn activation_receipt_reports_a_shadowing_directory_binding() {
        let (temporary, store, personal, work) = fixture();
        let project = temporary.path().join("project");
        std::fs::create_dir(&project)
            .unwrap_or_else(|error| panic!("create bound project: {error}"));
        let canonical_project = project
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonicalize project: {error}"));
        store
            .update_config(|config| {
                config.bindings.push(crate::model::Binding {
                    path: canonical_project,
                    context: personal.clone(),
                });
                Ok(())
            })
            .unwrap_or_else(|error| panic!("add binding: {error}"));
        let change = required_selection_change(&store, &work)
            .unwrap_or_else(|error| panic!("prepare activation: {error}"))
            .unwrap_or_else(|| panic!("profile change should require confirmation"));

        let receipt = activate_with_receipt(
            &store,
            &work,
            &SelectionConfirmation::Change(change),
            &project,
        )
        .unwrap_or_else(|error| panic!("activate with receipt: {error}"));

        assert_eq!(receipt.global_context(), &work);
        assert_eq!(receipt.effective_context(), &personal);
        assert_eq!(receipt.source(), ResolutionSource::DirectoryBinding);
        assert!(receipt.is_shadowed());
        assert_eq!(
            receipt.global_profiles()[0]
                .as_ref()
                .map(ProfileSelection::id)
                .map(ToString::to_string)
                .as_deref(),
            Some("claude:work")
        );
        assert_eq!(
            receipt.effective_profiles()[0]
                .as_ref()
                .map(ProfileSelection::id)
                .map(ToString::to_string)
                .as_deref(),
            Some("claude:personal")
        );
    }

    #[test]
    fn stale_billing_alias_still_rejects_a_changed_provider_selection() {
        let (_temporary, store, _personal, work) = fixture();
        let original_change = required_billing_change(&store, &work)
            .unwrap_or_else(|error| panic!("prepare activation: {error}"))
            .unwrap_or_else(|| panic!("profile change should require confirmation"));
        let codex_id: ProfileId = "codex:work"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile: {error}"));
        let codex_state = store
            .paths()
            .profile_state_dir(codex_id.provider(), codex_id.name());

        store
            .update_config(|config| {
                let codex_profile_uid = ProfileUid::for_state_dir(
                    &config.installation_uid,
                    codex_id.provider(),
                    &codex_state,
                )?;
                config.profiles.insert(
                    codex_id.clone(),
                    Profile::Codex {
                        profile_uid: codex_profile_uid,
                        billing_domain: BillingDomain::OpenaiApi,
                        auth: CodexAuth::ApiKey,
                        state_dir: codex_state,
                        secret_ref: Some("keyring://ctxlane/codex-work".to_owned()),
                        account_hint: None,
                        expected_workspace_id: None,
                        credential_store: CodexCredentialStore::File,
                        trusted_runners_only: false,
                        wif: None,
                        automation: AutomationPolicy::default(),
                    },
                );
                config
                    .contexts
                    .get_mut(&work)
                    .ok_or_else(|| Error::ContextNotFound(work.to_string()))?
                    .codex = Some(codex_id);
                Ok(())
            })
            .unwrap_or_else(|error| panic!("change target selection: {error}"));

        let fresh = required_billing_change(&store, &work)
            .unwrap_or_else(|error| panic!("refresh activation: {error}"))
            .unwrap_or_else(|| panic!("changed selection should require confirmation"));
        assert_ne!(original_change, fresh);
        let error = match activate(&store, &work, &BillingConfirmation::Change(original_change)) {
            Ok(()) => panic!("stale confirmation should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InteractionRequired(_)));
    }
}
