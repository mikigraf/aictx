use crate::{
    Error, Result,
    config::MetadataStore,
    model::{BillingDomain, Config, Context, Name, Profile, Provider},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BillingConfirmation {
    None,
    Change(BillingChange),
    AnyChange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BillingChange {
    previous: Name,
    target: Name,
    previous_domains: [Option<BillingDomain>; 2],
    target_domains: [Option<BillingDomain>; 2],
}

impl BillingChange {
    #[must_use]
    pub const fn previous(&self) -> &Name {
        &self.previous
    }

    #[must_use]
    pub const fn target(&self) -> &Name {
        &self.target
    }

    #[must_use]
    pub(crate) const fn previous_domains(&self) -> [Option<BillingDomain>; 2] {
        self.previous_domains
    }

    #[must_use]
    pub(crate) const fn target_domains(&self) -> [Option<BillingDomain>; 2] {
        self.target_domains
    }
}

/// Return a fingerprint of the billing change that must be confirmed, if any.
pub fn required_billing_change(
    store: &MetadataStore,
    target: &Name,
) -> Result<Option<BillingChange>> {
    let (config, state) = store.load_metadata()?;
    if !config.contexts.contains_key(target) {
        return Err(Error::ContextNotFound(target.to_string()));
    }
    let previous = state
        .current_context
        .as_ref()
        .or(config.default_context.as_ref());
    Ok(previous.and_then(|previous| {
        billing_change(&config, previous, target)
            .filter(|_| config.settings.require_billing_confirmation_on_change)
    }))
}

/// Select a context while rechecking the billing policy under the metadata lock.
pub fn activate(
    store: &MetadataStore,
    target: &Name,
    confirmation: &BillingConfirmation,
) -> Result<()> {
    store.update_metadata(|config, state| {
        if !config.contexts.contains_key(target) {
            return Err(Error::ContextNotFound(target.to_string()));
        }
        let previous = state
            .current_context
            .as_ref()
            .or(config.default_context.as_ref());
        let current_change = previous.and_then(|previous| billing_change(config, previous, target));
        if let Some(current_change) = current_change
            && config.settings.require_billing_confirmation_on_change
        {
            let confirmed = match confirmation {
                BillingConfirmation::AnyChange => true,
                BillingConfirmation::Change(expected) => expected == &current_change,
                BillingConfirmation::None => false,
            };
            if !confirmed {
                return Err(Error::InteractionRequired(
                    "billing-domain change requires confirmation; the active context may have changed"
                        .to_owned(),
                ));
            }
        }
        state.current_context = Some(target.clone());
        Ok(())
    })
}

fn billing_change(config: &Config, previous: &Name, target: &Name) -> Option<BillingChange> {
    if previous == target {
        return None;
    }
    let previous_domains = billing_domains(config, previous);
    let target_domains = billing_domains(config, target);
    (previous_domains != target_domains).then(|| BillingChange {
        previous: previous.clone(),
        target: target.clone(),
        previous_domains,
        target_domains,
    })
}

fn billing_domains(config: &Config, context: &Name) -> [Option<BillingDomain>; 2] {
    let context = config.contexts.get(context);
    [Provider::Claude, Provider::Codex].map(|provider| {
        context
            .and_then(|context: &Context| context.profile(provider))
            .and_then(|id| config.profiles.get(id))
            .map(Profile::billing_domain)
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::{
        config::{AppPaths, MetadataStore},
        model::{
            BillingDomain, ClaudeAuth, CodexAuth, CodexCredentialStore, Context, Name, Profile,
            ProfileId,
        },
    };

    use super::*;

    fn fixture() -> (TempDir, MetadataStore, Name, Name) {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::for_root(temporary.path().join("aictx"));
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
                config.profiles.insert(
                    personal_id.clone(),
                    Profile::Claude {
                        billing_domain: BillingDomain::ClaudeSubscription,
                        auth: ClaudeAuth::SubscriptionToken,
                        state_dir: personal_state,
                        secret_ref: Some("keyring://aictx/claude-personal".to_owned()),
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
                        state_dir: work_state,
                        secret_ref: Some("keyring://aictx/claude-work".to_owned()),
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

        (temporary, store, personal, work)
    }

    #[test]
    fn billing_change_requires_matching_confirmation() {
        let (_temporary, store, _personal, work) = fixture();
        let change = required_billing_change(&store, &work)
            .unwrap_or_else(|error| panic!("prepare activation: {error}"))
            .unwrap_or_else(|| panic!("billing change should require confirmation"));

        let error = match activate(&store, &work, &BillingConfirmation::None) {
            Ok(()) => panic!("unconfirmed activation should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InteractionRequired(_)));
        activate(&store, &work, &BillingConfirmation::Change(change))
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
    fn stale_billing_fingerprint_is_rejected() {
        let (_temporary, store, _personal, work) = fixture();
        let original_change = required_billing_change(&store, &work)
            .unwrap_or_else(|error| panic!("prepare activation: {error}"))
            .unwrap_or_else(|| panic!("billing change should require confirmation"));
        let codex_id: ProfileId = "codex:work"
            .parse()
            .unwrap_or_else(|error| panic!("valid profile: {error}"));
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
                        secret_ref: Some("keyring://aictx/codex-work".to_owned()),
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
            .unwrap_or_else(|error| panic!("change target billing: {error}"));

        let fresh = required_billing_change(&store, &work)
            .unwrap_or_else(|error| panic!("refresh activation: {error}"))
            .unwrap_or_else(|| panic!("changed billing should require confirmation"));
        assert_ne!(original_change, fresh);
        let error = match activate(&store, &work, &BillingConfirmation::Change(original_change)) {
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
}
