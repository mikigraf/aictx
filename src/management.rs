use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    Error, Result,
    config::{
        AppPaths, MetadataStore, OrderedProfileLocks, acquire_ordered_profile_locks,
        acquire_profile_lock, ensure_profile_automation_unfenced, ensure_secure_directory,
    },
    model::{
        AutomationPolicy, BillingDomain, Binding, ClaudeAuth, CodexAuth, CodexCredentialStore,
        CodexWifConfig, Context, Name, Profile, ProfileId, ProfileUid, Provider, WifConfig,
    },
    resolver::{canonical_directory, context_not_found},
    secret::SecretRef,
};

static STATE_DIRECTORY_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ValueEdit<T> {
    #[default]
    Keep,
    Clear,
    Set(T),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileDraft {
    Claude {
        name: Name,
        auth: ClaudeAuth,
        secret_ref: Option<SecretRef>,
        account_hint: Option<String>,
        expected_organization: Option<String>,
        wif: Option<WifConfig>,
    },
    Codex {
        name: Name,
        auth: CodexAuth,
        secret_ref: Option<SecretRef>,
        account_hint: Option<String>,
        expected_workspace_id: Option<String>,
        credential_store: CodexCredentialStore,
        trusted_runners_only: bool,
        wif: Option<CodexWifConfig>,
    },
}

impl ProfileDraft {
    #[must_use]
    pub const fn provider(&self) -> Provider {
        match self {
            Self::Claude { .. } => Provider::Claude,
            Self::Codex { .. } => Provider::Codex,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &Name {
        match self {
            Self::Claude { name, .. } | Self::Codex { name, .. } => name,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClaudeProfileEdit {
    pub account_hint: ValueEdit<String>,
    pub expected_organization: ValueEdit<String>,
    /// Explicit local-operator replacement. Interactive callers leave this unchanged.
    pub automation: Option<AutomationPolicy>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CodexProfileEdit {
    pub account_hint: ValueEdit<String>,
    pub expected_workspace_id: ValueEdit<String>,
    pub credential_store: Option<CodexCredentialStore>,
    pub trusted_runners_only: Option<bool>,
    /// Explicit local-operator replacement. Interactive callers leave this unchanged.
    pub automation: Option<AutomationPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileEdit {
    Claude(ClaudeProfileEdit),
    Codex(CodexProfileEdit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileReceipt {
    pub id: ProfileId,
    pub profile_uid: ProfileUid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRemovalReceipt {
    pub id: ProfileId,
    pub detached_state: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextReceipt {
    pub name: Name,
    pub context: Context,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingReceipt {
    pub binding: Binding,
}

pub fn add_profile(store: &MetadataStore, draft: ProfileDraft) -> Result<ProfileReceipt> {
    let paths = store.paths();
    let id = ProfileId::new(draft.provider(), draft.name().clone());
    let _profile_lock = acquire_profile_lock(&paths.profile_lock(id.provider(), id.name()), true)?;
    let profile_uid = store.update_config(|config| {
        reject_profile_name_collision(config.profiles.keys(), &id, None)?;
        let state_dir = allocate_profile_state_dir(config.profiles.values(), paths, id.provider())?;
        let profile_uid =
            ProfileUid::for_state_dir(&config.installation_uid, id.provider(), &state_dir)?;
        if config.retired_profile_uids.contains(&profile_uid)
            || config
                .profiles
                .values()
                .any(|profile| profile.profile_uid() == &profile_uid)
        {
            return Err(Error::ConfigBusy);
        }
        let profile = profile_from_draft(&id, profile_uid.clone(), state_dir, draft)?;
        config.profiles.insert(id.clone(), profile);

        // Validate every draft field before creating its private state directory. Once the
        // directory exists it is an immutable storage identity: an uncertain metadata-write
        // error must leave it detached instead of risking deletion after a successful commit.
        config.validate()?;
        let state_dir = config
            .profiles
            .get(&id)
            .ok_or(Error::ConfigBusy)?
            .state_dir();
        if !paths.is_managed_profile_state_dir(id.provider(), state_dir) {
            return Err(Error::InvalidConfig(format!(
                "profile `{id}` state_dir must be a managed immediate child beneath {}",
                paths.profile_state_root(id.provider()).display()
            )));
        }
        ensure_secure_directory(state_dir)?;
        Ok(profile_uid)
    })?;
    Ok(ProfileReceipt { id, profile_uid })
}

pub fn edit_profile(
    store: &MetadataStore,
    id: &ProfileId,
    expected: &Profile,
    edit: ProfileEdit,
) -> Result<ProfileReceipt> {
    let paths = store.paths();
    // Keep the legacy alias lock in the same exclusive lifecycle fence so a schema-v1
    // runner that only knows the alias lock cannot overlap a metadata edit after upgrade.
    let _profile_locks = acquire_resource_locks(
        [
            paths.profile_lock(id.provider(), id.name()),
            paths.profile_lifecycle_lock(expected.profile_uid()),
        ]
        .into_iter(),
    )?;
    ensure_profile_automation_unfenced(paths, expected.profile_uid())?;
    store.update_config(|config| {
        let profile = expected_profile_mut(config, id, expected)?;
        apply_profile_edit(profile, edit)?;
        Ok(())
    })?;
    Ok(ProfileReceipt {
        id: id.clone(),
        profile_uid: expected.profile_uid().clone(),
    })
}

pub fn rename_profile(
    store: &MetadataStore,
    old: &ProfileId,
    new_name: Name,
    expected: &Profile,
) -> Result<ProfileReceipt> {
    let paths = store.paths();
    let replacement = ProfileId::new(old.provider(), new_name);
    let _profile_locks = acquire_resource_locks(
        [
            paths.profile_lock(old.provider(), old.name()),
            paths.profile_lock(replacement.provider(), replacement.name()),
            paths.profile_lifecycle_lock(expected.profile_uid()),
        ]
        .into_iter(),
    )?;
    ensure_profile_automation_unfenced(paths, expected.profile_uid())?;
    store.update_config(|config| {
        let current = config.profiles.get(old).ok_or(Error::ConfigBusy)?;
        if current != expected {
            return Err(Error::ConfigBusy);
        }
        if &replacement == old {
            return Ok(());
        }
        reject_profile_name_collision(config.profiles.keys(), &replacement, Some(old))?;
        let profile = config.profiles.remove(old).ok_or(Error::ConfigBusy)?;
        config.profiles.insert(replacement.clone(), profile);
        for context in config.contexts.values_mut() {
            if context.claude.as_ref() == Some(old) {
                context.claude = Some(replacement.clone());
            }
            if context.codex.as_ref() == Some(old) {
                context.codex = Some(replacement.clone());
            }
        }
        Ok(())
    })?;
    Ok(ProfileReceipt {
        id: replacement,
        profile_uid: expected.profile_uid().clone(),
    })
}

pub fn remove_profile(
    store: &MetadataStore,
    id: &ProfileId,
    expected: &Profile,
) -> Result<ProfileRemovalReceipt> {
    remove_profile_with(store, id, expected, |_| Ok(())).map(|(receipt, ())| receipt)
}

pub(crate) fn remove_profile_with<T>(
    store: &MetadataStore,
    id: &ProfileId,
    expected: &Profile,
    after_remove: impl FnOnce(&Profile) -> Result<T>,
) -> Result<(ProfileRemovalReceipt, T)> {
    let paths = store.paths();
    let _profile_locks = acquire_resource_locks(
        [
            paths.profile_lock(id.provider(), id.name()),
            paths.profile_lifecycle_lock(expected.profile_uid()),
        ]
        .into_iter(),
    )?;
    ensure_profile_automation_unfenced(paths, expected.profile_uid())?;
    store.update_config(|config| {
        let current = config.profiles.get(id).ok_or(Error::ConfigBusy)?;
        if current != expected {
            return Err(Error::ConfigBusy);
        }
        ensure_profile_unreferenced(config, id)?;
        config.profiles.remove(id).ok_or(Error::ConfigBusy)?;
        config
            .retired_profile_uids
            .insert(expected.profile_uid().clone());
        Ok(())
    })?;

    let output = match after_remove(expected) {
        Ok(output) => output,
        Err(operation_error) => {
            let restore = store.update_config(|config| {
                if config.profiles.contains_key(id) {
                    return Err(Error::ConfigBusy);
                }
                if !config.retired_profile_uids.remove(expected.profile_uid()) {
                    return Err(Error::ConfigBusy);
                }
                config.profiles.insert(id.clone(), expected.clone());
                Ok(())
            });
            return match restore {
                Ok(()) => Err(operation_error),
                Err(restore_error) => Err(Error::PolicyRefused(format!(
                    "profile `{id}` metadata was removed, the requested cleanup failed ({operation_error}), and metadata rollback failed ({restore_error})"
                ))),
            };
        }
    };

    Ok((
        ProfileRemovalReceipt {
            id: id.clone(),
            detached_state: expected
                .state_dir()
                .exists()
                .then(|| expected.state_dir().to_path_buf()),
        },
        output,
    ))
}

pub fn add_context(store: &MetadataStore, name: Name, context: Context) -> Result<ContextReceipt> {
    store.update_config(|config| {
        if config.contexts.contains_key(&name) {
            return Err(Error::InvalidInput(format!(
                "context `{name}` already exists"
            )));
        }
        config.contexts.insert(name.clone(), context.clone());
        if config.default_context.is_none() {
            config.default_context = Some(name.clone());
        }
        Ok(())
    })?;
    Ok(ContextReceipt { name, context })
}

pub fn edit_context(
    store: &MetadataStore,
    name: &Name,
    expected: &Context,
    replacement: Context,
) -> Result<ContextReceipt> {
    store.update_config(|config| {
        let current = config.contexts.get_mut(name).ok_or(Error::ConfigBusy)?;
        if current != expected {
            return Err(Error::ConfigBusy);
        }
        *current = replacement.clone();
        Ok(())
    })?;
    Ok(ContextReceipt {
        name: name.clone(),
        context: replacement,
    })
}

pub fn rename_context(
    store: &MetadataStore,
    old: &Name,
    new: Name,
    expected: &Context,
) -> Result<ContextReceipt> {
    store.update_metadata(|config, state| {
        let current = config.contexts.get(old).ok_or(Error::ConfigBusy)?;
        if current != expected {
            return Err(Error::ConfigBusy);
        }
        if &new == old {
            return Ok(());
        }
        if state.current_context.as_ref() == Some(old) {
            return Err(Error::InvalidInput(format!(
                "context `{old}` is active; use another context first"
            )));
        }
        if config.contexts.contains_key(&new) {
            return Err(Error::InvalidInput(format!(
                "context `{new}` already exists"
            )));
        }
        let context = config.contexts.remove(old).ok_or(Error::ConfigBusy)?;
        config.contexts.insert(new.clone(), context);
        if config.default_context.as_ref() == Some(old) {
            config.default_context = Some(new.clone());
        }
        for binding in &mut config.bindings {
            if &binding.context == old {
                binding.context = new.clone();
            }
        }
        Ok(())
    })?;
    Ok(ContextReceipt {
        name: new,
        context: expected.clone(),
    })
}

pub fn remove_context(
    store: &MetadataStore,
    name: &Name,
    expected: &Context,
) -> Result<ContextReceipt> {
    store.update_metadata(|config, state| {
        let current = config.contexts.get(name).ok_or(Error::ConfigBusy)?;
        if current != expected {
            return Err(Error::ConfigBusy);
        }
        if state.current_context.as_ref() == Some(name) {
            return Err(Error::InvalidInput(format!(
                "context `{name}` is active; use another context first"
            )));
        }
        if config
            .bindings
            .iter()
            .any(|binding| &binding.context == name)
        {
            return Err(Error::InvalidInput(format!(
                "context `{name}` is referenced by a directory binding"
            )));
        }
        config.contexts.remove(name).ok_or(Error::ConfigBusy)?;
        if config.default_context.as_ref() == Some(name) {
            config.default_context = config.contexts.keys().next().cloned();
        }
        Ok(())
    })?;
    Ok(ContextReceipt {
        name: name.clone(),
        context: expected.clone(),
    })
}

pub fn add_binding(store: &MetadataStore, path: &Path, context: Name) -> Result<BindingReceipt> {
    let path = canonical_directory(path)?;
    let binding = Binding { path, context };
    store.update_config(|config| {
        if !config.contexts.contains_key(&binding.context) {
            return Err(context_not_found(config, &binding.context));
        }
        if config
            .bindings
            .iter()
            .any(|existing| existing.path == binding.path)
        {
            return Err(Error::InvalidInput(format!(
                "binding for {} already exists",
                binding.path.display()
            )));
        }
        config.bindings.push(binding.clone());
        Ok(())
    })?;
    Ok(BindingReceipt { binding })
}

pub fn edit_binding(
    store: &MetadataStore,
    expected: &Binding,
    path: &Path,
    context: Name,
) -> Result<BindingReceipt> {
    let path = canonical_directory(path)?;
    let replacement = Binding { path, context };
    store.update_config(|config| {
        if !config.contexts.contains_key(&replacement.context) {
            return Err(context_not_found(config, &replacement.context));
        }
        let index = config
            .bindings
            .iter()
            .position(|binding| binding.path == expected.path)
            .ok_or(Error::ConfigBusy)?;
        if &config.bindings[index] != expected {
            return Err(Error::ConfigBusy);
        }
        if config
            .bindings
            .iter()
            .enumerate()
            .any(|(candidate, binding)| candidate != index && binding.path == replacement.path)
        {
            return Err(Error::InvalidInput(format!(
                "binding for {} already exists",
                replacement.path.display()
            )));
        }
        config.bindings[index] = replacement.clone();
        Ok(())
    })?;
    Ok(BindingReceipt {
        binding: replacement,
    })
}

pub fn remove_binding(store: &MetadataStore, expected: &Binding) -> Result<BindingReceipt> {
    store.update_config(|config| {
        let index = config
            .bindings
            .iter()
            .position(|binding| binding.path == expected.path)
            .ok_or(Error::ConfigBusy)?;
        if &config.bindings[index] != expected {
            return Err(Error::ConfigBusy);
        }
        config.bindings.remove(index);
        Ok(())
    })?;
    Ok(BindingReceipt {
        binding: expected.clone(),
    })
}

fn profile_from_draft(
    id: &ProfileId,
    profile_uid: ProfileUid,
    state_dir: PathBuf,
    draft: ProfileDraft,
) -> Result<Profile> {
    match draft {
        ProfileDraft::Claude {
            auth,
            secret_ref,
            account_hint,
            expected_organization,
            wif,
            ..
        } => {
            let secret_ref = match auth {
                ClaudeAuth::SubscriptionToken | ClaudeAuth::ApiKey => Some(
                    secret_ref
                        .unwrap_or_else(|| SecretRef::default_for(id))
                        .to_string(),
                ),
                ClaudeAuth::Wif => {
                    if secret_ref.is_some() {
                        return Err(Error::InvalidInput(
                            "WIF profiles do not store static secrets".to_owned(),
                        ));
                    }
                    let metadata = wif.as_ref().ok_or_else(|| {
                        Error::InvalidInput("WIF profiles require WIF metadata".to_owned())
                    })?;
                    metadata.validate_enrollment(id)?;
                    None
                }
            };
            Ok(Profile::Claude {
                profile_uid,
                billing_domain: match auth {
                    ClaudeAuth::SubscriptionToken => BillingDomain::ClaudeSubscription,
                    ClaudeAuth::ApiKey | ClaudeAuth::Wif => BillingDomain::AnthropicApi,
                },
                auth,
                state_dir,
                secret_ref,
                account_hint,
                expected_organization,
                wif,
                automation: AutomationPolicy::default(),
            })
        }
        ProfileDraft::Codex {
            auth,
            secret_ref,
            account_hint,
            expected_workspace_id,
            credential_store,
            trusted_runners_only,
            wif,
            ..
        } => {
            let secret_ref = match auth {
                CodexAuth::ApiKey | CodexAuth::AccessToken => Some(
                    secret_ref
                        .unwrap_or_else(|| SecretRef::default_for(id))
                        .to_string(),
                ),
                CodexAuth::ChatgptOauth | CodexAuth::Wif => {
                    if secret_ref.is_some() {
                        return Err(Error::InvalidInput(
                            "vendor-managed authentication must not persist a static secret"
                                .to_owned(),
                        ));
                    }
                    if auth == CodexAuth::Wif {
                        let metadata = wif.as_ref().ok_or_else(|| {
                            Error::InvalidInput(
                                "Codex WIF profiles require WIF metadata".to_owned(),
                            )
                        })?;
                        metadata.validate_enrollment(id)?;
                    }
                    None
                }
            };
            Ok(Profile::Codex {
                profile_uid,
                billing_domain: match auth {
                    CodexAuth::ApiKey => BillingDomain::OpenaiApi,
                    CodexAuth::Wif | CodexAuth::ChatgptOauth | CodexAuth::AccessToken => {
                        BillingDomain::ChatgptSubscription
                    }
                },
                auth,
                state_dir,
                secret_ref,
                account_hint,
                expected_workspace_id,
                credential_store,
                trusted_runners_only,
                wif,
                automation: AutomationPolicy::default(),
            })
        }
    }
}

fn apply_profile_edit(profile: &mut Profile, edit: ProfileEdit) -> Result<()> {
    match (profile, edit) {
        (
            Profile::Claude {
                account_hint,
                expected_organization,
                automation,
                ..
            },
            ProfileEdit::Claude(edit),
        ) => {
            apply_value_edit(account_hint, edit.account_hint);
            apply_value_edit(expected_organization, edit.expected_organization);
            if let Some(replacement) = edit.automation {
                *automation = replacement;
            }
            Ok(())
        }
        (
            Profile::Codex {
                account_hint,
                expected_workspace_id,
                credential_store,
                trusted_runners_only,
                automation,
                ..
            },
            ProfileEdit::Codex(edit),
        ) => {
            apply_value_edit(account_hint, edit.account_hint);
            apply_value_edit(expected_workspace_id, edit.expected_workspace_id);
            if let Some(value) = edit.credential_store {
                *credential_store = value;
            }
            if let Some(value) = edit.trusted_runners_only {
                *trusted_runners_only = value;
            }
            if let Some(replacement) = edit.automation {
                *automation = replacement;
            }
            Ok(())
        }
        _ => Err(Error::InvalidInput(
            "profile edit does not match the profile provider".to_owned(),
        )),
    }
}

fn apply_value_edit<T>(target: &mut Option<T>, edit: ValueEdit<T>) {
    match edit {
        ValueEdit::Keep => {}
        ValueEdit::Clear => *target = None,
        ValueEdit::Set(value) => *target = Some(value),
    }
}

fn expected_profile_mut<'a>(
    config: &'a mut crate::model::Config,
    id: &ProfileId,
    expected: &Profile,
) -> Result<&'a mut Profile> {
    let current = config.profiles.get_mut(id).ok_or(Error::ConfigBusy)?;
    if current != expected {
        return Err(Error::ConfigBusy);
    }
    Ok(current)
}

fn reject_profile_name_collision<'a>(
    mut profiles: impl Iterator<Item = &'a ProfileId>,
    candidate: &ProfileId,
    excluded: Option<&ProfileId>,
) -> Result<()> {
    if let Some(existing) = profiles.find(|existing| {
        excluded != Some(*existing)
            && existing.provider() == candidate.provider()
            && existing
                .name()
                .as_str()
                .eq_ignore_ascii_case(candidate.name().as_str())
    }) {
        if existing == candidate {
            return Err(Error::InvalidInput(format!(
                "profile `{candidate}` already exists"
            )));
        }
        return Err(Error::InvalidInput(format!(
            "profile `{candidate}` conflicts with existing `{existing}` on case-insensitive filesystems"
        )));
    }
    Ok(())
}

fn allocate_profile_state_dir<'a>(
    profiles: impl Iterator<Item = &'a Profile>,
    paths: &AppPaths,
    provider: Provider,
) -> Result<PathBuf> {
    let occupied = profiles
        .map(|profile| profile.state_dir().to_path_buf())
        .collect::<Vec<_>>();
    for _ in 0..128 {
        let generation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = STATE_DIRECTORY_GENERATION.fetch_add(1, Ordering::Relaxed);
        let leaf = format!(
            "p-{generation:032x}-{:08x}-{counter:016x}",
            std::process::id()
        );
        let candidate = paths.profile_state_root(provider).join(leaf);
        if !candidate.exists() && !occupied.iter().any(|path| path == &candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::ConfigBusy)
}

fn acquire_resource_locks(
    lock_paths: impl Iterator<Item = PathBuf>,
) -> Result<OrderedProfileLocks> {
    acquire_ordered_profile_locks(lock_paths.map(|path| (path, true)))
}

fn ensure_profile_unreferenced(config: &crate::model::Config, id: &ProfileId) -> Result<()> {
    for (context_name, context) in &config.contexts {
        if context.claude.as_ref() == Some(id) || context.codex.as_ref() == Some(id) {
            return Err(Error::InvalidInput(format!(
                "profile `{id}` is still referenced by context `{context_name}`"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "management/tests.rs"]
mod tests;
