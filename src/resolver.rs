use std::{env, path::Path};

use crate::{
    Error, Result,
    model::{Config, MutableState, Name, Profile, ProfileId, Provider},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionSource {
    ExplicitProfile,
    ExplicitContext,
    DirectoryBinding,
    ActiveContext,
    DefaultContext,
}

impl ResolutionSource {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExplicitProfile => "explicit profile",
            Self::ExplicitContext => "explicit context",
            Self::DirectoryBinding => "directory binding",
            Self::ActiveContext => "active context",
            Self::DefaultContext => "default context",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedContext {
    pub name: Name,
    pub source: ResolutionSource,
}

#[derive(Clone, Debug)]
pub struct ResolvedProfile {
    pub id: ProfileId,
    pub profile: Profile,
    pub context: Option<Name>,
    pub source: ResolutionSource,
}

pub fn resolve_profile(
    config: &Config,
    state: &MutableState,
    cwd: &Path,
    provider: Provider,
    explicit_context: Option<&Name>,
    explicit_profile: Option<&ProfileId>,
) -> Result<ResolvedProfile> {
    if let Some(profile_id) = explicit_profile {
        if profile_id.provider() != provider {
            return Err(Error::InvalidInput(format!(
                "profile `{profile_id}` cannot be used for provider `{provider}`"
            )));
        }
        let profile = config
            .profiles
            .get(profile_id)
            .ok_or_else(|| Error::ProfileNotFound(profile_id.to_string()))?;
        return Ok(ResolvedProfile {
            id: profile_id.clone(),
            profile: profile.clone(),
            context: None,
            source: ResolutionSource::ExplicitProfile,
        });
    }

    let resolved_context = resolve_context(config, state, cwd, explicit_context)?;
    let context = config
        .contexts
        .get(&resolved_context.name)
        .ok_or_else(|| Error::ContextNotFound(resolved_context.name.to_string()))?;
    let profile_id = context.profile(provider).ok_or_else(|| {
        Error::ProfileNotFound(format!(
            "context `{}` has no {provider} profile",
            resolved_context.name
        ))
    })?;
    let profile = config
        .profiles
        .get(profile_id)
        .ok_or_else(|| Error::ProfileNotFound(profile_id.to_string()))?;

    Ok(ResolvedProfile {
        id: profile_id.clone(),
        profile: profile.clone(),
        context: Some(resolved_context.name),
        source: resolved_context.source,
    })
}

pub fn resolve_context(
    config: &Config,
    state: &MutableState,
    cwd: &Path,
    explicit: Option<&Name>,
) -> Result<ResolvedContext> {
    if let Some(name) = explicit {
        ensure_context_exists(config, name)?;
        return Ok(ResolvedContext {
            name: name.clone(),
            source: ResolutionSource::ExplicitContext,
        });
    }

    let canonical_cwd = cwd.canonicalize().map_err(|source| Error::ReadFile {
        path: cwd.to_path_buf(),
        source,
    })?;
    if let Some(binding) = config
        .bindings
        .iter()
        .filter(|binding| canonical_cwd.starts_with(&binding.path))
        .max_by_key(|binding| binding.path.components().count())
    {
        return Ok(ResolvedContext {
            name: binding.context.clone(),
            source: ResolutionSource::DirectoryBinding,
        });
    }

    if let Some(name) = &state.current_context {
        ensure_context_exists(config, name)?;
        return Ok(ResolvedContext {
            name: name.clone(),
            source: ResolutionSource::ActiveContext,
        });
    }

    if let Some(name) = &config.default_context {
        ensure_context_exists(config, name)?;
        return Ok(ResolvedContext {
            name: name.clone(),
            source: ResolutionSource::DefaultContext,
        });
    }

    Err(Error::ContextNotFound(
        "no explicit, bound, active, or default context is configured".to_owned(),
    ))
}

pub fn current_directory() -> Result<std::path::PathBuf> {
    env::current_dir().map_err(|source| Error::ReadFile {
        path: std::path::PathBuf::from("."),
        source,
    })
}

pub fn canonical_directory(path: &Path) -> Result<std::path::PathBuf> {
    let path = path.canonicalize().map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = path.metadata().map_err(|source| Error::ReadFile {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(Error::InvalidInput(format!(
            "binding target {} is not a directory",
            path.display()
        )));
    }
    Ok(path)
}

fn ensure_context_exists(config: &Config, name: &Name) -> Result<()> {
    if config.contexts.contains_key(name) {
        Ok(())
    } else {
        Err(Error::ContextNotFound(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::TempDir;

    use crate::model::{Binding, Context};

    use super::*;

    fn config_with_contexts() -> Config {
        let mut config = Config::default();
        let personal = Name::parse("personal")
            .unwrap_or_else(|error| panic!("valid name should parse: {error}"));
        let work =
            Name::parse("work").unwrap_or_else(|error| panic!("valid name should parse: {error}"));
        config.contexts = BTreeMap::from([
            (
                personal,
                Context {
                    claude: Some(
                        "claude:personal"
                            .parse()
                            .unwrap_or_else(|error| panic!("valid profile: {error}")),
                    ),
                    codex: None,
                },
            ),
            (
                work,
                Context {
                    claude: Some(
                        "claude:work"
                            .parse()
                            .unwrap_or_else(|error| panic!("valid profile: {error}")),
                    ),
                    codex: None,
                },
            ),
        ]);
        config
    }

    #[test]
    fn closest_binding_wins_over_active_context() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let parent = temporary.path().join("company");
        let child = parent.join("special");
        std::fs::create_dir_all(&child)
            .unwrap_or_else(|error| panic!("create test directories: {error}"));
        let mut config = config_with_contexts();
        config.bindings = vec![
            Binding {
                path: parent
                    .canonicalize()
                    .unwrap_or_else(|error| panic!("canonical parent: {error}")),
                context: Name::parse("personal")
                    .unwrap_or_else(|error| panic!("valid name: {error}")),
            },
            Binding {
                path: child
                    .canonicalize()
                    .unwrap_or_else(|error| panic!("canonical child: {error}")),
                context: Name::parse("work").unwrap_or_else(|error| panic!("valid name: {error}")),
            },
        ];
        let state = MutableState {
            version: crate::model::SCHEMA_VERSION,
            current_context: Some(
                Name::parse("personal").unwrap_or_else(|error| panic!("valid name: {error}")),
            ),
        };

        let resolved = resolve_context(&config, &state, &child, None)
            .unwrap_or_else(|error| panic!("context should resolve: {error}"));
        assert_eq!(resolved.name.as_str(), "work");
        assert_eq!(resolved.source, ResolutionSource::DirectoryBinding);
    }
}
